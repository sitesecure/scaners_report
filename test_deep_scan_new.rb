require 'net/http' 
require 'action_mailer'
require 'rubygems'
require 'rake'
require 'sqlite3'
require 'json'
require 'hashie'
require 'csv'
 
# ruby -r "./test_deep_scan_new.rb" -e "Start.check" 
 
class Notifier < ActionMailer::Base
    default from: 'test@ss.com'
    ActionMailer::Base.delivery_method = :smtp
    ActionMailer::Base.perform_deliveries = true  
    ActionMailer::Base.smtp_settings = {
    :address              => "smtp.gmail.com",
    :port                 => "587",
    :domain               => 'gmail.com',
    :user_name            => 'support@sitesecure.ru',
    :password             => '8lKGJ&&29ejsd',
    :authentication       => 'plain',
    :enable_starttls_auto => true  }

    def welcome(recipient, head, body)
      @recipient = recipient
      attachments['json.log'] = File.read('./json.log')
      mail(to: recipient,
           subject: "#{head}",
           body: "#{body}")
    end
    
  end
 
class Start
  
    def self.check
      @message_body = String.new
      @json_log = String.new 
      
      csv = CSV.read("./data_deep.csv", :headers=>true)
      
      csv.each do |expected|  
        uri = URI("http://sitesecure:sitesecure123@ssmaster4.cloudapp.net:8000/ScalableScannerApp/scans/")
        
        http = Net::HTTP.new(uri.host, uri.port)
        
        request = Net::HTTP::Post.new(uri)
        request.basic_auth 'sitesecure', 'sitesecure123'
        request.set_form_data({"url" => expected['url'], "pages_requested" => "10", "check_timeout" => "20"})
        response = http.request(request)
  
        # print response.body;
        
        if (response.code != "201") 
          print "\n" << expected['url']
          print " <- broken ("
          print response.code
          print ")"
          next
        end
        
        hash = JSON.parse response.body
        obj = Hashie::Mash.new hash
        id = obj.id
        
        uri = URI("http://sitesecure:sitesecure123@ssmaster4.cloudapp.net:8000/ScalableScannerApp/scans/" + id.to_s + "/?format=json")

        http = Net::HTTP.new(uri.host, uri.port)
        #http.use_ssl = true
        #http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        
        request = Net::HTTP::Get.new(uri.request_uri)
        
        # Wait when request will be finished

        sleep(300)
        response = http.request(request)
                    
        hash = JSON.parse response.body
        obj = Hashie::Mash.new hash
        
        if (obj.status != 2)
        
          result = [2, 2, 2, 2, 2, 2]
        
        else
          
          pageIds = getPagesIds(id)
          result = getScanInfo(pageIds)
          
        end
        
        print "\n" << expected['url']
        
        result.each { |x| print ", " << x.to_s }
        
       # @json_log << "Site: " + expected['url'] + "\n"
       # @json_log << "Response: " 
       # @json_log << response.body
       # @json_log << "\n\n" 
        
        #uri = URI("https://sitesecure.ru/scan/07e3b2bf-b0cc-4647-8806-4fc96e1d2bfc.json")

        #http = Net::HTTP.new(uri.host, uri.port)
        #http.use_ssl = true
        #http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        
        #request = Net::HTTP::Get.new(uri.request_uri)
        #response = http.request(request)
        
        #p response.body
        #p "\n\n"
        
        #hash = JSON.parse response.body
        #obj = Hashie::Mash.new hash
        
       # data = obj.data
        
       # @message_body << validate_item(data, 'WebsiteEvent::Virustotal', to_boolean(expected['WebsiteEvent::Virustotal']))
       # @message_body << validate_item_with_provider(data, 'WebsiteEvent::Safebrowsing', to_boolean(expected['WebsiteEvent::Safebrowsing::google']), 'google')
       # @message_body << validate_item_with_provider(data, 'WebsiteEvent::Safebrowsing', to_boolean(expected['WebsiteEvent::Safebrowsing::yandex']), 'yandex')
       # @message_body << validate_item(data, 'WebsiteEvent::MobileRedirect', to_boolean(expected['WebsiteEvent::MobileRedirect']))
       # @message_body << validate_item(data, 'WebsiteEvent::LinkToBlacklist', to_boolean(expected['WebsiteEvent::LinkToBlacklist']))
       # @message_body << validate_item(data, 'WebsiteEvent::StaticLinkToBlacklist', to_boolean(expected['WebsiteEvent::StaticLinkToBlacklist']))
       # @message_body << validate_item(data, 'WebsiteEvent::DynamicLinkToBlacklist', to_boolean(expected['WebsiteEvent::DynamicLinkToBlacklist']))
       # @message_body << validate_item(data, 'WebsiteEvent::SeoRedirect', to_boolean(expected['WebsiteEvent::SeoRedirect']))

      end
      
     # File.write('./json.log', @json_log)
     # print @message_body
      
      if (@message_body.include? "item is missed") or (@message_body.include? "not expected value")
        # Notifier.welcome("konstantin_b_v@mail.ru", "Test results - failed", @message_body).deliver
        # Notifier.welcome("konstantin_b_v@mail.ru, oleg.nevstruev@gmail.com, vlad@sitesecure.ru", "Test results - failed", @message_body).deliver_now
      else
        # Notifier.welcome("konstantin_b_v@mail.ru", "Test results - passed", @message_body).deliver
        # Notifier.welcome("konstantin_b_v@mail.ru, oleg.nevstruev@gmail.com, vlad@sitesecure.ru", "Test results - passed", @message_body).deliver_now
      end
    end
    
    def self.getPagesIds(scanId) 
      uri = URI("http://sitesecure:sitesecure123@ssmaster4.cloudapp.net:8000/ScalableScannerApp/scans/" << scanId.to_s << "/pages/?format=json")

      http = Net::HTTP.new(uri.host, uri.port)
      #http.use_ssl = true
      #http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        
      request = Net::HTTP::Get.new(uri.request_uri)
      response = http.request(request)
        
      #p response.body
      #p "\n\n"
        
      hash = JSON.parse response.body
      obj = Hashie::Mash.new hash
        
      data = obj.page_scans
      
      #p data
      
      return data;
    end
    
    def self.getScanInfo(pageIds)
      
      res = [-1, -1, -1, -1, -1, -1]
      
      pageIds.each do |pageId|
        uri = URI("http://sitesecure:sitesecure123@ssmaster4.cloudapp.net:8000/ScalableScannerApp/page_scans/" << pageId.to_s << "/?format=json")

        http = Net::HTTP.new(uri.host, uri.port)
        #http.use_ssl = true
        #http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          
        request = Net::HTTP::Get.new(uri.request_uri)
        response = http.request(request)
          
        #p response.body
        #p "\n\n"
          
        hash = JSON.parse response.body
        obj = Hashie::Mash.new hash
          
        data = obj.checks
        #p data
        #p "---"
        #p data[0].check_name
        #p data[0].result
        
        #GSB
        #YSB
        #Mobile redirect на блек лист
        #regular_redirect_to_blacklist
        #static_links_to_blacklist
        #static_links_to_blacklist
        
        for i in 0..9
          if data[i].check_name == "gsb" and res[0] < data[i].result.to_i
            res[0] = data[i].result.to_i
            break;
          end             
          
          if data[i].check_name == "ysb" and res[1] < data[i].result.to_i
            res[1] = data[i].result.to_i
            break  
          end
          
          if data[i].check_name == "mobile_redirect_to_blacklist" and res[2] < data[i].result.to_i
            res[2] = data[i].result.to_i
            break  
          end
          
          if data[i].check_name == "regular_redirect_to_blacklist" and res[3] < data[i].result.to_i
            res[3] = data[i].result.to_i
            break  
          end
          
          if data[i].check_name == "static_links_to_blacklist" and res[4] < data[i].result.to_i
            res[4] = data[i].result.to_i
            break  
          end
          
          if data[i].check_name == "dynamic_links_to_blacklist" and res[5] < data[i].result.to_i
            res[5] = data[i].result.to_i
            break  
          end
        end
        
      end 
      
      #p res
      return res;
    end
    
    def self.validate_item(data,source,expected_value)
        @result = String.new
        
        @result <<  "\nValidating item : "
        @result <<  source
        if data.each_index.select{|i| data[i].source == source} == []
          @result << " - item is missed"
        else
          if data[data.each_index.select{|i| data[i].source == source}[0]].vulnerable? == expected_value 
            @result << " - passed"
          else
            @result << " - not expected value : "
            @result << to_string(data[data.each_index.select{|i| data[i].source == source}[0]].vulnerable?)
          end    
        end
        
        return @result
    end
    
    def self.validate_item_with_provider(data,source,expected_value,provider)
        @result = String.new
      
        @result <<  "\nValidating item : "
        @result <<  source
        @result <<  "::"
        @result <<  provider
        if data.each_index.select{|i| data[i].source == source && data[i].info.provider == provider} == []
          @result <<  " - item is missed" 
        else 
          if data[data.each_index.select{|i| data[i].source == source && data[i].info.provider == provider}[0]].vulnerable? == expected_value 
            @result << " - passed"
          else
            @result <<  " - not expected value : "
            @result <<  to_string(data[data.each_index.select{|i| data[i].source == source && data[i].info.provider == provider}[0]].vulnerable?)
          end    
        end
        
        return @result
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
