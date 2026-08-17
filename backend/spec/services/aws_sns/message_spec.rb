require "rails_helper"

RSpec.describe AwsSns::Message do
  subject(:message) { described_class.new(body.to_json) }

  let(:body) { signed_sns_message }

  describe "#verified?" do
    context "with a message Amazon signed" do
      before { stub_sns_certificate }

      it "accepts SignatureVersion 2" do
        expect(message).to be_verified
      end

      it "accepts SignatureVersion 1" do
        body = signed_sns_message("SignatureVersion" => "1")

        expect(described_class.new(body.to_json)).to be_verified
      end

      it "accepts a SubscriptionConfirmation" do
        body = signed_sns_message(type: "SubscriptionConfirmation")

        expect(described_class.new(body.to_json)).to be_verified
      end

      it "accepts a Notification carrying a Subject, which is signed only when present" do
        body = signed_sns_message("Subject" => "Amazon SES Bounce Notification")

        expect(described_class.new(body.to_json)).to be_verified
      end
    end

    context "with a message that was tampered with after signing" do
      before { stub_sns_certificate }

      it "rejects an edited Message" do
        body["Message"] = {"notificationType" => "Bounce", "mail" => {"destination" => ["victim@example.com"]}}.to_json

        expect(message).not_to be_verified
      end

      it "rejects an edited TopicArn" do
        body["TopicArn"] = "arn:aws:sns:us-east-1:999999999999:attacker"

        expect(message).not_to be_verified
      end

      it "rejects an edited Type" do
        body["Type"] = "SubscriptionConfirmation"

        expect(message).not_to be_verified
      end

      it "rejects a Subject added after signing" do
        body["Subject"] = "injected"

        expect(message).not_to be_verified
      end

      it "rejects a signature signed by some other key" do
        body["Signature"] = Base64.strict_encode64(
          OpenSSL::PKey::RSA.new(2048).sign(OpenSSL::Digest.new("SHA256"), sns_string_to_sign(body))
        )

        expect(message).not_to be_verified
      end

      it "rejects a missing signature" do
        body.delete("Signature")

        expect(message).not_to be_verified
      end

      it "rejects a signature that is not valid base64" do
        body["Signature"] = "!!!not base64!!!"

        expect(message).not_to be_verified
      end
    end

    context "with a SigningCertURL we should not dereference" do
      it "rejects a host outside amazonaws.com without fetching it" do
        body["SigningCertURL"] = "https://sns.us-east-1.amazonaws.com.attacker.test/cert.pem"
        stub = stub_request(:get, body["SigningCertURL"])

        expect(message).not_to be_verified
        expect(stub).not_to have_been_requested
      end

      it "rejects a plain http URL without fetching it" do
        body["SigningCertURL"] = "http://sns.us-east-1.amazonaws.com/cert.pem"
        stub = stub_request(:get, body["SigningCertURL"])

        expect(message).not_to be_verified
        expect(stub).not_to have_been_requested
      end

      it "rejects a file URL" do
        body["SigningCertURL"] = "file:///etc/passwd"

        expect(message).not_to be_verified
      end

      it "rejects an internal address" do
        body["SigningCertURL"] = "https://169.254.169.254/latest/meta-data/"
        stub = stub_request(:get, body["SigningCertURL"])

        expect(message).not_to be_verified
        expect(stub).not_to have_been_requested
      end

      it "rejects a missing URL" do
        body.delete("SigningCertURL")

        expect(message).not_to be_verified
      end

      it "rejects a host that only borrows Amazon's as a prefix, whatever its case" do
        body["SigningCertURL"] = "https://SNS.us-east-1.amazonaws.com.attacker.test/cert.pem"
        stub = stub_request(:get, body["SigningCertURL"])

        expect(message).not_to be_verified
        expect(stub).not_to have_been_requested
      end

      it "accepts Amazon's host spelled in mixed case" do
        url = "https://SNS.us-east-1.amazonaws.com/cert.pem"
        body["SigningCertURL"] = url
        body["Signature"] = sns_signature(body)
        stub_sns_certificate(url: url)

        expect(described_class.new(body.to_json)).to be_verified
      end
    end

    context "when the certificate cannot be used" do
      it "rejects a certificate that 404s" do
        stub_sns_certificate(status: 404, body: "not found")

        expect(message).not_to be_verified
      end

      it "rejects a response that is not a certificate" do
        stub_sns_certificate(body: "nonsense")

        expect(message).not_to be_verified
      end

      it "rejects when the fetch fails outright" do
        stub_request(:get, AwsSnsHelpers::CERTIFICATE_URL).to_raise(SocketError)

        expect(message).not_to be_verified
      end
    end

    context "with a payload we cannot make sense of" do
      before { stub_sns_certificate }

      it "rejects an unknown SignatureVersion" do
        body = signed_sns_message("SignatureVersion" => "3")

        expect(described_class.new(body.to_json)).not_to be_verified
      end

      it "rejects an unknown Type" do
        expect(described_class.new({"Type" => "Whatever"}.to_json)).not_to be_verified
      end

      it "rejects malformed JSON" do
        expect(described_class.new("{not json")).not_to be_verified
      end

      it "rejects a JSON body that is not an object" do
        expect(described_class.new("[1, 2, 3]")).not_to be_verified
      end

      it "rejects an empty body" do
        expect(described_class.new("")).not_to be_verified
      end

      it "rejects nil" do
        expect(described_class.new(nil)).not_to be_verified
      end
    end

    context "when AWS_SNS_TOPIC_ARN pins the topic" do
      before { stub_sns_certificate }

      it "accepts a message on the configured topic" do
        with_env("AWS_SNS_TOPIC_ARN" => AwsSnsHelpers::TOPIC_ARN) do
          expect(message).to be_verified
        end
      end

      it "rejects a correctly signed message on some other topic" do
        with_env("AWS_SNS_TOPIC_ARN" => "arn:aws:sns:us-east-1:123456789012:something-else") do
          expect(message).not_to be_verified
        end
      end
    end
  end

  describe "#confirm_subscription" do
    subject(:message) { described_class.new(body.to_json) }

    let(:body) { signed_sns_message(type: "SubscriptionConfirmation") }

    it "fetches an Amazon SubscribeURL" do
      stub = stub_request(:get, AwsSnsHelpers::SUBSCRIBE_URL).to_return(status: 200, body: "")

      expect(message.confirm_subscription).to be true
      expect(stub).to have_been_requested
    end

    # The bug this class exists to close: SubscribeURL used to reach Kernel#open,
    # which spawns a subprocess for anything starting with a pipe.
    it "does not execute a command when SubscribeURL is a pipe" do
      marker = Rails.root.join("tmp", "sns_command_injection_#{SecureRandom.hex(4)}")
      body["SubscribeURL"] = "|touch #{marker}"

      expect(message.confirm_subscription).to be false
      expect(File.exist?(marker)).to be false
    end

    it "refuses a host outside amazonaws.com" do
      body["SubscribeURL"] = "https://attacker.test/confirm"
      stub = stub_request(:get, body["SubscribeURL"])

      expect(message.confirm_subscription).to be false
      expect(stub).not_to have_been_requested
    end

    it "refuses an internal address" do
      body["SubscribeURL"] = "https://169.254.169.254/latest/meta-data/"
      stub = stub_request(:get, body["SubscribeURL"])

      expect(message.confirm_subscription).to be false
      expect(stub).not_to have_been_requested
    end

    it "refuses a missing URL" do
      body.delete("SubscribeURL")

      expect(message.confirm_subscription).to be false
    end

    it "reports failure when the fetch fails" do
      stub_request(:get, AwsSnsHelpers::SUBSCRIBE_URL).to_raise(Net::OpenTimeout)

      expect(message.confirm_subscription).to be false
    end
  end
end
