require 'omniauth'
require 'mindbody-api'
require 'uri'
require 'net/http'

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
            email = request.params['email']
            password = request.params['password']
            url = URI("https://api.mindbodyonline.com/public/v6/usertoken/issue")

            http = Net::HTTP.new(url.host, url.port)
            http.use_ssl = true
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE

            req = Net::HTTP::Post.new(url)
            req["Content-Type"] = 'application/json'
            req["Api-Key"] = ENV['HARDPRESSED_API_ACCESS_TOKEN']
            req["SiteId"] = ENV['MINDBODY_SITE_IDS']
            req.body = "{\r\n\t\"Username\": \"#{email}\",\r\n\t\"Password\": \"#{password}\"\r\n}"
            res = http.request(req)

            return fail!(:invalid_credentials) if res.nil? || res.code != "200"
            auth = JSON.parse(res.body)
            userId=auth["User"]["Id"]

            url = URI("https://api.mindbodyonline.com/public/v6/staff/staff")
            http = Net::HTTP.new(url.host, url.port)
            http.use_ssl = true
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE

            req = Net::HTTP::Get.new(url)
            req["Api-Key"] = ENV['HARDPRESSED_API_ACCESS_TOKEN']
            req["SiteId"] = ENV['MINDBODY_SITE_IDS']
            res = http.request(req)
          end

          return fail!(:invalid_credentials) if res.nil? || res.code != "200"
          coaches = JSON.parse(res.body)["StaffMembers"]
          for coach in coaches
            @raw_info = coach if coach["Id"] == userId
          end

          super
        rescue Exception => e
          return fail!(:mindbody_error, e)
        end
      end

      uid { raw_info["Id"].to_s }

      info do
        {
            :name => raw_info["Name"],
            :first_name => raw_info["FirstName"],
            :last_name => raw_info["LastName"],
            :email => raw_info["Email"],
            :phone => raw_info["HomePhone"] || raw_info["MobilePhone"],
            :location => raw_info["City"].nil? ? "#{raw_info["City"]}, #{raw_info["State"]}" : raw_info["State"],
            :nickname => raw_info["Name"],
            :image => raw_info["ImageUrl"]
        }
      end

      credentials do
        {:guid => raw_info["Id"].to_s }
      end

      extra do
        {:raw_info => raw_info,
         :login_type => login_type}
      end

      def raw_info
        @raw_info
      end

      # def profile
      #   @profile ||= raw_info[:client] || raw_info[:staff_members]
      # end

      def login_type
        'staff'
      end
    end
  end
end

OmniAuth.config.add_camelization('mindbody', 'MindBody')
