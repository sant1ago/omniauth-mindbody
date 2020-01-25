require 'omniauth'
require 'mindbody-api'

module OmniAuth
  module Strategies
    class MindBody
      include OmniAuth::Strategy

      option :fields, [:email, :password]
      option :enable_client_logins, true
      option :enable_staff_logins, true

      def request_phase
        form = OmniAuth::Form.new(:title => "User Info", :url => callback_path)
        options.fields.each do |field|
          form.text_field field.to_s.capitalize.gsub("_", " "), field.to_s
        end
        form.button "Sign In"
        form.to_response
      end

      def callback_phase
        begin
          res = nil
          if options.enable_client_logins
            res = ::MindBody::Services::ClientService.validate_login(request.params['email'], request.params['password'])
          end

          if (res.status != "Success" || res.nil?) && options.enable_staff_logins
            # res = ::MindBody::Services::StaffService.get_staff('StaffCredentials' => {'Username' => request.params['email'],
            #                                                                           'Password' => request.params['password'],
            #                                                                           'SiteIDs' => {'int' => ::MindBody.configuration.site_ids}})
            response = MindBody::Services::StaffService.get_staff()
          end

          return false if response.nil? || response.status != "Success"

          @raw_info ||= response.result[:staff_members].where(email: login_params['email']) #response.result
          super
        rescue Exception => e
          return fail!(:mindbody_error, e)
        end
      end

      uid { profile.id.to_s }

      info do
        {
          :name => profile.name,
          :first_name => profile.first_name,
          :last_name => profile.last_name,
          :email => profile.email,
          :phone => profile.home_phone || profile.mobile_phone,
          :location => profile.city.nil? ? "#{profile.city}, #{profile.state}" : profile.state,
          :nickname => profile.username,
          :image => profile.photo_url
        }
      end

      credentials do
        {:guid => raw_info[:guid].to_s }
      end

      extra do
        {:raw_info => raw_info,
         :login_type => login_type}
      end

      def raw_info
        @raw_info
      end

      def profile
        @profile ||= raw_info[:client] || raw_info[:staff_members]
      end

      def login_type
        case
        when raw_info.has_key?(:client)
          'client'
        when raw_info.has_key?(:staff_members)
          'staff'
        else
          'unknown'
        end
      end
    end
  end
end

OmniAuth.config.add_camelization('mindbody', 'MindBody')
