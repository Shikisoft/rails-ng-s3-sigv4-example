var app = angular.module('uploadApp');

app.controller("PhotosController", [
   '$scope', '$http', 'Upload',  
  function( $scope, $http, Upload ) {
    

    // Uploads file directly to S3 bucket
    $scope.uploadPhoto= function(){

      // Get policy, signature, credentials and algorithm
      $http.get( "/policy.json").then(
          function(response) {
            
            Upload.upload({
                url: 'https://'+response.data.s3_region_endpoint+'/'+response.data.bucket_name,
                method: 'POST',
                data: {
                  key: $scope.file.name,
                  acl: 'private',
                  "Content-Type": $scope.file.type != '' ? $scope.file.type : 'application/octet-stream',
                  'X-Amz-Credential': response.data.x_amz_credential,
                  'X-Amz-Algorithm': response.data.x_amz_algorithm,
                  'X-Amz-Date': response.data.x_amz_date,
                  'Policy': response.data.policy,
                  'X-Amz-Signature': response.data.x_amz_signature,
                  file: $scope.file

                }
            }).then(
              function(response) {
              },
              function(response) {
              },
              function (evt) {
                $scope.progressPercentage = parseInt(100.0 * evt.loaded / evt.total);
              }
            );
            
            
          },
          function(response) {
          }
      );
      
    };
    
    $scope.selectFile = function(file, errFiles) {
        
      $scope.errFile = errFiles && errFiles[0];
      
      if(file && !$scope.errFile){
        $scope.file = file;
        $scope.uploadPhoto();
      }
      else if($scope.errFile){
          $scope.file = null;
      }
            
    };

    



  }
]);