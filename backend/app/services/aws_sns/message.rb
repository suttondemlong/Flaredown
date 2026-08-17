require "net/http"

module AwsSns
  # An Amazon SNS message, as delivered to the SES notification webhook.
  #
  # That endpoint is necessarily unauthenticated, so the signature Amazon
  # attaches is the only thing separating a genuine SES bounce notification from
  # an arbitrary POST by an arbitrary caller. Nothing here should be acted on
  # before #verified? returns true.
  #
  # https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
  class Message
    # Amazon publishes signing certificates under sns.<region>.amazonaws.com and
    # nowhere else. Pinning the host is what keeps SigningCertURL from aiming us
    # at an attacker's certificate, and SubscribeURL from aiming us at an
    # internal address.
    AMAZON_HOST = /\Asns\.[a-z0-9-]+\.amazonaws\.com\z/

    # The fields the signature covers, in the order the string to sign lists
    # them. Fields absent from the message are skipped: Subject is optional on a
    # Notification.
    SIGNED_FIELDS = {
      "Notification" => %w[Message MessageId Subject Timestamp TopicArn Type],
      "SubscriptionConfirmation" => %w[Message MessageId SubscribeURL Timestamp Token TopicArn Type],
      "UnsubscribeConfirmation" => %w[Message MessageId SubscribeURL Timestamp Token TopicArn Type]
    }.freeze

    # SignatureVersion 1 is SHA1, 2 is SHA256. Anything else is something we have
    # no way to check, so it does not get the benefit of the doubt.
    DIGESTS = {"1" => "SHA1", "2" => "SHA256"}.freeze

    NETWORK_ERRORS = [
      SocketError,
      SystemCallError,
      Net::OpenTimeout,
      Net::ReadTimeout,
      OpenSSL::SSL::SSLError
    ].freeze

    HTTP_TIMEOUT = 5
    CERTIFICATE_TTL = 1.day

    attr_reader :raw_post

    def initialize(raw_post)
      @raw_post = raw_post
      @body = parse(raw_post)
    end

    def type
      @body["Type"]
    end

    def topic_arn
      @body["TopicArn"]
    end

    # True only when Amazon signed this exact payload, and signed it on the topic
    # we expect. Every reason to say no is a plain false: the caller is anonymous
    # and has no business learning which check it tripped.
    def verified?
      return false unless SIGNED_FIELDS.key?(type)
      return false unless expected_topic?

      digest = DIGESTS[@body["SignatureVersion"]]
      return false if digest.nil?

      certificate = certificate_from(@body["SigningCertURL"])
      return false if certificate.nil?

      certificate.public_key.verify(OpenSSL::Digest.new(digest), signature, string_to_sign)
    rescue OpenSSL::OpenSSLError
      false
    end

    # SNS delivers nothing on a topic until the subscription is confirmed by
    # fetching this URL once. Returns false if the URL is not one of Amazon's,
    # which on a verified message should not happen.
    def confirm_subscription
      uri = amazon_uri(@body["SubscribeURL"])
      return false if uri.nil?

      get(uri).is_a?(Net::HTTPSuccess)
    rescue *NETWORK_ERRORS
      false
    end

    private

    def parse(raw_post)
      parsed = JSON.parse(raw_post.to_s)
      parsed.is_a?(Hash) ? parsed : {}
    rescue JSON::ParserError
      {}
    end

    # Pinning the topic stops a valid signature from some unrelated SNS topic
    # driving our bounce handling. Skipped when unconfigured so that existing
    # deployments keep working.
    def expected_topic?
      expected = ENV["AWS_SNS_TOPIC_ARN"]

      expected.blank? || topic_arn == expected
    end

    def signature
      Base64.decode64(@body["Signature"].to_s)
    end

    def string_to_sign
      SIGNED_FIELDS.fetch(type).each_with_object(+"") do |field, string|
        next unless @body.key?(field)

        string << field << "\n" << @body[field].to_s << "\n"
      end
    end

    def certificate_from(url)
      uri = amazon_uri(url)
      return nil if uri.nil?

      pem = cached_certificate(uri)
      return nil if pem.nil?

      OpenSSL::X509::Certificate.new(pem)
    rescue OpenSSL::X509::CertificateError, *NETWORK_ERRORS
      nil
    end

    # Written to the cache only on success, so that a bad response is not held on
    # to for a day.
    def cached_certificate(uri)
      key = "aws_sns/certificate/#{uri}"
      cached = Rails.cache.read(key)
      return cached if cached.present?

      response = get(uri)
      return nil unless response.is_a?(Net::HTTPSuccess)

      Rails.cache.write(key, response.body, expires_in: CERTIFICATE_TTL)
      response.body
    end

    def amazon_uri(value)
      uri = URI.parse(value.to_s)
      return nil unless uri.is_a?(URI::HTTPS)
      # URI leaves the host's case alone; DNS does not care about it. Anchoring
      # still rejects sns.us-east-1.amazonaws.com.attacker.test.
      return nil unless AMAZON_HOST.match?(uri.host.to_s.downcase)

      uri
    rescue URI::InvalidURIError
      nil
    end

    # Net::HTTP does not follow redirects, which is what we want: an open
    # redirect on an Amazon host should not become a way out of AMAZON_HOST.
    def get(uri)
      Net::HTTP.start(
        uri.host,
        uri.port,
        use_ssl: true,
        open_timeout: HTTP_TIMEOUT,
        read_timeout: HTTP_TIMEOUT
      ) { |http| http.request(Net::HTTP::Get.new(uri)) }
    end
  end
end
