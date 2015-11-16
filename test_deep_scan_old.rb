require 'net/http' 
require 'action_mailer'
require 'rubygems'
require 'rake'
require 'sqlite3'
require 'json'
require 'hashie'
require 'csv'
 
class Notifier < ActionMailer::Base
    default from: 'test@ss.com'
    ActionMailer::Base.delivery_method = :smtp
    ActionMailer::Base.perform_deliveries = true  
    ActionMailer::Base.smtp_settings = {
    :address              => "smtp.gmail.com",
    :port                 => "587",
    :domain               => 'gmail.com',
    :user_name            => 'support@sitesecure.ru',
    :password             => '\'d6&n:3-t6_T$7qZ',
    :authentication       => 'plain',
    :enable_starttls_auto => true  }

    def welcome(recipient, head, body)
      @recipient = recipient
      mail(to: recipient,
           subject: "#{head}",
           body: "#{body}")
    end
    
  end
 
class Start
  
    def self.check
      @message_body = String.new                       
      verifications = ['WebsiteEvent::Safebrowsing', 'WebsiteEvent::Safebrowsing', 'WebsiteEvent::MobileRedirect', 'WebsiteEvent::LinkToBlacklist', 'WebsiteEvent::StaticLinkToBlacklist', 'WebsiteEvent::DynamicLinkToBlacklist', 'WebsiteEvent::Virustotal']
      
      csv = CSV.read("./data_deep.csv", :headers=>true)
      
      csv.each do |expected|
        res = [-1, -1, -1, -1, -1, -1, -1]
          
        @message_body << "\nValidate url : "
        @message_body << expected['url']
        uri = URI("https://sitesecure.ru/scan.json")
        
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        
        request = Net::HTTP::Post.new(uri)
        request.set_form_data({"scan[name]" => expected['url']})
        response = http.request(request)
  
        # print response.body;
        
        hash = JSON.parse response.body
        obj = Hashie::Mash.new hash
        
        uri = URI(obj.url.sub! 'http:', 'https:')

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        
        request = Net::HTTP::Get.new(uri.request_uri)
        @message_body << "(" + uri.to_s + ")"
        
        # Wait when request will be finished
        begin
          sleep(10)
          response = http.request(request)
                    
          hash = JSON.parse response.body
          obj = Hashie::Mash.new hash
        
          #print "\n--> " + obj.state
          
        end while obj.state == 'progress'
        
        #uri = URI("https://sitesecure.ru/scan/07e3b2bf-b0cc-4647-8806-4fc96e1d2bfc.json")

        #http = Net::HTTP.new(uri.host, uri.port)
        #http.use_ssl = true
        #http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        
        #request = Net::HTTP::Get.new(uri.request_uri)
        #response = http.request(request)
        
        #p response.body
        #p "\n\n"
        
        hash = JSON.parse response.body
        obj = Hashie::Mash.new hash
        
        data = obj.data
        
          if data.each_index.select{|i| data[i].source == verifications[0] && data[i].info.provider == "google"} == []
            res[0] = 2 
          else
            if data[data.each_index.select{|i| data[i].source == verifications[0] && data[i].info.provider == "google"}[0]].vulnerable? == false 
              res[0] = 0
            else
              res[0] = 1
            end    
          end
          
          if data.each_index.select{|i| data[i].source == verifications[1] && data[i].info.provider == "yandex"} == []
            res[1] = 2 
          else 
            if data[data.each_index.select{|i| data[i].source == verifications[1] && data[i].info.provider == "yandex"}[0]].vulnerable? == false 
              res[1] = 0
            else
              res[1] = 1
            end    
          end
         
        for j in 2..6
          if data.each_index.select{|i| data[i].source == verifications[j]} == []
            res[j] = 2 
          else
            if data[data.each_index.select{|i| data[i].source == verifications[j]}[0]].vulnerable? == false 
              res[j] = 0
            else
              res[j] = 1
            end    
          end
        end
        
        print expected['url']
        
        res.each { |x| print ", " << x.to_s }
        p ', '
        
        #if data[i].check_name == "gsb" and res[0] < data[i].result.to_i
        #if data[i].check_name == "ysb" and res[1] < data[i].result.to_i
        #if data[i].check_name == "mobile_redirect_to_blacklist" and res[2] < data[i].result.to_i
        #if data[i].check_name == "regular_redirect_to_blacklist" and res[3] < data[i].result.to_i
        #if data[i].check_name == "static_links_to_blacklist" and res[4] < data[i].result.to_i
        #if data[i].check_name == "dynamic_links_to_blacklist" and res[5] < data[i].result.to_i
        
        #@message_body << validate_item(data, 'WebsiteEvent::Virustotal', to_boolean(expected['WebsiteEvent::Virustotal']))
        #@message_body << validate_item_with_provider(data, 'WebsiteEvent::Safebrowsing', to_boolean(expected['WebsiteEvent::Safebrowsing::google']), 'google')
        #@message_body << validate_item_with_provider(data, 'WebsiteEvent::Safebrowsing', to_boolean(expected['WebsiteEvent::Safebrowsing::yandex']), 'yandex')
        #@message_body << validate_item(data, 'WebsiteEvent::MobileRedirect', to_boolean(expected['WebsiteEvent::MobileRedirect']))
        #@message_body << validate_item(data, 'WebsiteEvent::LinkToBlacklist', to_boolean(expected['WebsiteEvent::LinkToBlacklist']))
        #@message_body << validate_item(data, 'WebsiteEvent::StaticLinkToBlacklist', to_boolean(expected['WebsiteEvent::StaticLinkToBlacklist']))
        #@message_body << validate_item(data, 'WebsiteEvent::DynamicLinkToBlacklist', to_boolean(expected['WebsiteEvent::DynamicLinkToBlacklist']))
        #@message_body << validate_item(data, 'WebsiteEvent::SeoRedirect', to_boolean(expected['WebsiteEvent::SeoRedirect']))

      end
      
      #print @message_body
      # vlad@sitesecure.ru, oleg.nevstruev@gmail.com
      # Notifier.welcome("konstantin_b_v@mail.ru", "Test results", @message_body).deliver
    end
    
    def self.validate_item(data,source,expected_value)
        @result = String.new
        
        @result << "\nValidating item : "
        @result << source
        if data.each_index.select{|i| data[i].source == source} == []
          @result << " - item is missed" 
        else 
          if data[data.each_index.select{|i| data[i].source == source}[0]].vulnerable? == expected_value 
            @result << " - as expected (value = "
            @result << to_string(expected_value)
            @result << ")"
          else
            @result << " - expected value = "
            @result << to_string(expected_value)
            @result << "; observed value = "
            @result << to_string(data[data.each_index.select{|i| data[i].source == 'WebsiteEvent::Virustotal'}[0]].vulnerable?)
          end    
        end
        
        return @result
    end
    
    def self.validate_item_with_provider(data,source,expected_value,provider)
        @result <<  "\nValidating item : "
        @result <<  source
        if data.each_index.select{|i| data[i].source == source && data[i].info.provider == provider} == []
          @result <<  " - item is missed" 
        else 
          if data[data.each_index.select{|i| data[i].source == source && data[i].info.provider == provider}[0]].vulnerable? == expected_value 
            @result <<  " - as expected (value = "
            @result <<  to_string(expected_value)
            @result <<  ")"
          else
            @result <<  " - expected value = "
            @result <<  to_string(expected_value)
            @result <<  "; observed value = "
            @result <<  to_string(data[data.each_index.select{|i| data[i].source == 'WebsiteEvent::Virustotal'}[0]].vulnerable?)
          end    
        end
    end
    
    def self.to_boolean(str)
     return true if str=="true"
     return false if str=="false"
     return nil
    end
    
    def self.to_string(bool)
     return "true" if bool==true
     return "false" if bool==false
     return nil
    end
end
