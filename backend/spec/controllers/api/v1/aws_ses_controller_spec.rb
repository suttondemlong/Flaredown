require "rails_helper"

describe Api::V1::AwsSesController, type: :controller do
  # SNS posts a bare JSON body, and signs that exact byte sequence.
  def post_notification(body)
    request.headers["CONTENT_TYPE"] = "application/json"
    post :notification, body: body.is_a?(String) ? body : body.to_json
  end

  describe "POST #notification" do
    context "with a Notification Amazon signed" do
      before { stub_sns_certificate }

      it "accepts it and hands the payload to the dispatcher" do
        body = signed_sns_message

        expect(EmailRejectDispatcher).to receive(:perform_async).with(body.to_json)

        post_notification(body)

        expect(response).to have_http_status(:ok)
      end

      it "needs no credentials" do
        expect(EmailRejectDispatcher).to receive(:perform_async)

        post_notification(signed_sns_message)

        expect(response).to have_http_status(:ok)
      end

      it "returns an empty body" do
        allow(EmailRejectDispatcher).to receive(:perform_async)

        post_notification(signed_sns_message)

        expect(response.body).to be_empty
      end
    end

    context "with a SubscriptionConfirmation Amazon signed" do
      before { stub_sns_certificate }

      it "confirms the subscription by fetching the URL" do
        stub = stub_request(:get, AwsSnsHelpers::SUBSCRIBE_URL).to_return(status: 200, body: "")

        post_notification(signed_sns_message(type: "SubscriptionConfirmation"))

        expect(response).to have_http_status(:ok)
        expect(stub).to have_been_requested
      end

      it "does not dispatch a rejection" do
        stub_request(:get, AwsSnsHelpers::SUBSCRIBE_URL).to_return(status: 200, body: "")

        expect(EmailRejectDispatcher).not_to receive(:perform_async)

        post_notification(signed_sns_message(type: "SubscriptionConfirmation"))
      end
    end

    context "with a message Amazon did not sign" do
      it "refuses an unsigned payload" do
        expect(EmailRejectDispatcher).not_to receive(:perform_async)

        post_notification({"Type" => "Notification", "Message" => "{}"})

        expect(response).to have_http_status(:forbidden)
      end

      it "refuses a payload edited after signing" do
        stub_sns_certificate
        body = signed_sns_message
        body["Message"] = {"notificationType" => "Bounce", "mail" => {"destination" => ["victim@example.com"]}}.to_json

        expect(EmailRejectDispatcher).not_to receive(:perform_async)

        post_notification(body)

        expect(response).to have_http_status(:forbidden)
      end

      it "refuses an empty body" do
        post_notification("")

        expect(response).to have_http_status(:forbidden)
      end

      it "refuses malformed JSON" do
        post_notification("{not json")

        expect(response).to have_http_status(:forbidden)
      end
    end

    # Regression tests for the reason this endpoint was rewritten. SubscribeURL
    # used to be handed to Kernel#open, which spawns a subprocess for a string
    # beginning with a pipe, on an endpoint that requires no credentials.
    context "given a SubscribeURL that used to reach Kernel#open" do
      let(:marker) { Rails.root.join("tmp", "aws_ses_command_injection_#{SecureRandom.hex(4)}") }

      after { FileUtils.rm_f(marker) }

      it "executes nothing for an unsigned pipe URL" do
        post_notification({"Type" => "SubscriptionConfirmation", "SubscribeURL" => "|touch #{marker}"})

        expect(response).to have_http_status(:forbidden)
        expect(File.exist?(marker)).to be false
      end

      it "executes nothing even when the rest of the message is signed" do
        stub_sns_certificate

        post_notification(signed_sns_message(:type => "SubscriptionConfirmation", "SubscribeURL" => "|touch #{marker}"))

        expect(response).to have_http_status(:ok)
        expect(File.exist?(marker)).to be false
      end
    end

    # The header is not covered by the signature, so it must not be able to pick
    # which branch runs.
    context "with an x-amz-sns-message-type header that disagrees with the body" do
      before { stub_sns_certificate }

      it "follows the signed Type, not the header" do
        stub = stub_request(:get, AwsSnsHelpers::SUBSCRIBE_URL)

        expect(EmailRejectDispatcher).to receive(:perform_async)

        request.headers["x-amz-sns-message-type"] = "SubscriptionConfirmation"
        post_notification(signed_sns_message(type: "Notification"))

        expect(response).to have_http_status(:ok)
        expect(stub).not_to have_been_requested
      end

      it "does not fall over when the header is absent" do
        allow(EmailRejectDispatcher).to receive(:perform_async)

        post_notification(signed_sns_message)

        expect(response).to have_http_status(:ok)
      end
    end
  end
end
