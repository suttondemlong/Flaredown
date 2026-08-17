# Builds genuinely signed SNS payloads, so that the signature check is exercised
# against real RSA rather than a stub of itself.
module AwsSnsHelpers
  CERTIFICATE_URL = "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-testcert.pem"
  TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:flaredown-ses"
  SUBSCRIBE_URL = "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&Token=abc123"

  # Deliberately not AwsSns::Message::SIGNED_FIELDS. If the implementation signs
  # the wrong fields, these specs should fail rather than agree with it.
  SIGNED_FIELDS = {
    "Notification" => %w[Message MessageId Subject Timestamp TopicArn Type],
    "SubscriptionConfirmation" => %w[Message MessageId SubscribeURL Timestamp Token TopicArn Type],
    "UnsubscribeConfirmation" => %w[Message MessageId SubscribeURL Timestamp Token TopicArn Type]
  }.freeze

  class << self
    # Generated once for the whole suite: RSA keygen is slow enough to notice.
    def key
      @key ||= OpenSSL::PKey::RSA.new(2048)
    end

    def certificate
      @certificate ||= begin
        certificate = OpenSSL::X509::Certificate.new
        certificate.version = 2
        certificate.serial = 1
        certificate.subject = OpenSSL::X509::Name.parse("/CN=sns.us-east-1.amazonaws.com")
        certificate.issuer = certificate.subject
        certificate.public_key = key.public_key
        certificate.not_before = Time.now - 1.hour
        certificate.not_after = Time.now + 1.hour
        certificate.sign(key, OpenSSL::Digest.new("SHA256"))
        certificate
      end
    end
  end

  # ClimateControl is not in the bundle, and the Gemfile belongs to the Rails
  # upgrade branch for now.
  def with_env(values)
    original = values.keys.to_h { |key| [key, ENV[key]] }
    values.each { |key, value| ENV[key] = value }

    yield
  ensure
    original.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
  end

  def stub_sns_certificate(url: AwsSnsHelpers::CERTIFICATE_URL, status: 200, body: nil)
    stub_request(:get, url).to_return(status: status, body: body || AwsSnsHelpers.certificate.to_pem)
  end

  # A payload carrying a valid signature over its own contents. Pass overrides to
  # change a field before it is signed; pass them after calling this to forge.
  def signed_sns_message(type: "Notification", **overrides)
    body = default_sns_body(type).merge(
      "SignatureVersion" => "2",
      "SigningCertURL" => AwsSnsHelpers::CERTIFICATE_URL
    ).merge(overrides.transform_keys(&:to_s))

    body.merge("Signature" => sns_signature(body))
  end

  def sns_signature(body)
    digest = (body["SignatureVersion"] == "1") ? OpenSSL::Digest::SHA1 : OpenSSL::Digest::SHA256

    Base64.strict_encode64(AwsSnsHelpers.key.sign(digest.new, sns_string_to_sign(body)))
  end

  def sns_string_to_sign(body)
    AwsSnsHelpers::SIGNED_FIELDS.fetch(body["Type"]).each_with_object(+"") do |field, string|
      next unless body.key?(field)

      string << field << "\n" << body[field].to_s << "\n"
    end
  end

  private

  def default_sns_body(type)
    common = {
      "Type" => type,
      "MessageId" => SecureRandom.uuid,
      "TopicArn" => AwsSnsHelpers::TOPIC_ARN,
      "Timestamp" => Time.current.iso8601
    }

    if type == "Notification"
      common.merge(
        "Message" => {"notificationType" => "Bounce", "mail" => {"destination" => ["bounced@example.com"]}}.to_json
      )
    else
      common.merge(
        "Message" => "You have chosen to subscribe to the topic #{AwsSnsHelpers::TOPIC_ARN}.",
        "Token" => SecureRandom.hex(16),
        "SubscribeURL" => AwsSnsHelpers::SUBSCRIBE_URL
      )
    end
  end
end

RSpec.configure do |config|
  config.include AwsSnsHelpers
end
