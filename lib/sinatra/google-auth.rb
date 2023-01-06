require 'omniauth-google-oauth2'
require 'openid/store/filesystem'
require 'securerandom'

module Sinatra
  module GoogleAuth

    class Middleware
      def initialize(app)
        @app = app
      end

      def call(env)
        if env['rack.session']["user"] || env['REQUEST_PATH'] =~ /\/auth\/google_oauth2/
          @app.call(env)
        else
          env['rack.session']['google-auth-redirect'] = env['REQUEST_PATH']
          location = File.join(env['REQUEST_PATH'], '/auth/google_oauth2')
          return [301, {'Content-Type' => 'text/html', 'Location' => location}, []]
        end
      end
    end

    module Helpers
      def authenticate
        unless session["user"]
          session['google-auth-redirect'] = request.path
          if settings.absolute_redirect?
            redirect "/auth/google_oauth2"
          else
            redirect to "/auth/google_oauth2"
          end
        end
      end
      
      def handle_authentication_callback
        unless session["user"]
          user_info = request.env["omniauth.auth"].info
          on_user(user_info) if respond_to? :on_user
          session["user"] = Array(user_info.email).first.downcase
        end
        
        url = session['google-auth-redirect'] || to("/")
        redirect url
      end
    end
    
    def self.secret
      ENV['SESSION_SECRET'] || ENV['SECURE_KEY'] || SecureRandom.hex(64)
    end
    
    def self.registered(app)
      raise "Must supply ENV var GOOGLE_CLIENT_ID" unless ENV['GOOGLE_CLIENT_ID']
      raise "Must supply ENV var GOOGLE_CLIENT_SECRET" unless ENV['GOOGLE_CLIENT_SECRET']
      app.helpers GoogleAuth::Helpers
      app.use ::Rack::Session::Cookie, :secret => secret
      app.use ::OmniAuth::Builder do
        provider :google_oauth2, ENV['GOOGLE_CLIENT_ID'], ENV['GOOGLE_CLIENT_SECRET']
      end
      
      app.set :absolute_redirect, false

      app.get "/auth/:provider/callback" do
        handle_authentication_callback
      end
      
      app.post "/auth/:provider/callback" do
        handle_authentication_callback
      end

      app.get "/auth/google_oauth2" do
        <<-HTML
        <html>
          <head>
            <script>
              window.onload = function() {
                var form = document.createElement('form');
                form.setAttribute('method', 'post');
                form.setAttribute('action', '/auth/google_oauth2');

                var input = document.createElement('input')
                input.setAttribute('type', 'hidden');
                input.setAttribute('name', 'authenticity_token')
                input.setAttribute('value', '#{Rack::Protection::AuthenticityToken.token(env['rack.session'])}')
                
                form.appendChild(input);

                document.body.appendChild(form);
                form.submit();
              }
            </script>
          </head>
          <body></body>
        </html>
        HTML
      end
    end
  end
  
  register GoogleAuth
end
