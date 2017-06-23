class PolicyController < ApplicationController
  
  # GET /policy.json
  def index
    
    # Construct variable that will be used
    s3_region =  ENV["AWS_REGION"]
    bucket = ENV["S3_UPLOAD_BUCKET"]
    
    current_dt = DateTime.now
    policy_date = current_dt.utc.strftime("%Y%m%d")
    x_amz_date = current_dt.utc.strftime("%Y%jT%H%M%SZ")
    x_amz_algorithm = "AWS4-HMAC-SHA256"
    x_amz_credential = "#{ENV['AWS_ACCESS_KEY_ID']}/#{policy_date}/#{s3_region}/s3/aws4_request"    
    
    encoded_policy = get_encoded_policy_document( bucket, x_amz_algorithm, x_amz_credential, x_amz_date )
    x_amz_signature = get_signature( policy_date, s3_region, encoded_policy )
    
    
    render json: {
      bucket_name: bucket,
      s3_region_endpoint: get_s3_region_endpoint(s3_region),
      x_amz_algorithm: x_amz_algorithm,
      x_amz_credential: x_amz_credential,
      x_amz_date: x_amz_date,
      x_amz_expires: 86400,
      x_amz_signature: x_amz_signature,
      policy:    encoded_policy
    }
  end
  
  private
    def get_signature_key( key, date_stamp, region_name, service_name )
      # This is the AWS algorithm to generate signature key. 
      # Inputs:
      #   key: Secret access key of your IAM user that has programmatic access and permissions to the bucket. If this is wrong, AWS will be unable to decrypt the policy and upload will be unsuccessfull.
      #   date_stamp: 8-digit string representing date of the request, in year (YYYY), month (MM), day (DD) format, such as 20170511.
      #   region_name: The region where the bucket belongs to. For example: eu-central-1
      #   service_name: The service that the signature_key is generated for. For this example it will simply be "s3"
      
        k_date = OpenSSL::HMAC.digest('sha256', "AWS4" + key, date_stamp)
        k_region = OpenSSL::HMAC.digest('sha256', k_date, region_name)
        k_service = OpenSSL::HMAC.digest('sha256', k_region, service_name)
        k_signing = OpenSSL::HMAC.digest('sha256', k_service, "aws4_request")
        k_signing
    end
    
    def get_encoded_policy_document( bucket, x_amz_algorithm, x_amz_credential, x_amz_date )
      # Creates a policy document with an expiration of 1 hour from inputs.
      # Inputs:
      #   bucket: Amazon S3 bucket name that the policy generated for
      #   x_amz_algorithm: The signing algorithm used during signature calculation.
      #   x_amz_credential: The credentials used for calculating signature.
      #   x_amz_date: The date of the signature in the ISO8601 formatted string.
      
      Base64.encode64( 
        {
          "expiration" => 1.hour.from_now.utc.xmlschema,
          "conditions" => [
            { "bucket" =>  bucket },
            [ "starts-with", "$key", "" ],
            { "acl" => "private" },
            [ "starts-with", "$Content-Type", "" ],
            {"x-amz-algorithm" => x_amz_algorithm },
            {"x-amz-credential" => x_amz_credential },
            {"x-amz-date" => x_amz_date},
            [ "content-length-range", 0, 524288000 ]
          ]
        }.to_json 
      ).gsub("\n","")
    end
    
    def get_signature( policy_date, s3_region, encoded_policy )
      # Gets signature key and Base64 encoded policy document. Then signs the policy document with signature key.
      # Returns resulting signature
      # Inputs:
      #   policy_date: 8-digit string representing date of the request, in year (YYYY), month (MM), day (DD) format, such as 20170511.
      #   s3_region: The region where the bucket belongs to. For example: eu-central-1
      #   encoded_policy: Encoded policy json file that will be signed
      
      # Gets signature key that will be used in signing
      signature_key = get_signature_key( ENV['AWS_SECRET_ACCESS_KEY'], policy_date , s3_region, "s3")

      # Sign and return the signature
      OpenSSL::HMAC.hexdigest('sha256', signature_key, encoded_policy )
    end
    
    def get_s3_region_endpoint(region_name)
      # Returns S3 endpoint for the region
      
      case region_name
      when "us-east-1"
        "s3.amazonaws.com"
      else
        "s3.#{region_name}.amazonaws.com"
      end
      
    end
    
end
