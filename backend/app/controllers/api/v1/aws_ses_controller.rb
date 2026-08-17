module Api
  module V1
    class AwsSesController < ApplicationController
      skip_authorize_resource only: [:notification]
      skip_before_action :authenticate_user!, only: [:notification]

      def notification
        message = AwsSns::Message.new(request.raw_post)

        # Amazon is the only caller entitled to anything here, and an unsigned
        # request is indistinguishable from an attacker's.
        return head :forbidden unless message.verified?

        # Dispatch on the signed Type rather than the x-amz-sns-message-type
        # header. The header is not covered by the signature, so letting it pick
        # the branch would hand back what verifying the signature just bought.
        case message.type
        when "SubscriptionConfirmation"
          message.confirm_subscription
        when "Notification"
          EmailRejectDispatcher.perform_async(message.raw_post)
        end

        head :ok
      end
    end
  end
end
