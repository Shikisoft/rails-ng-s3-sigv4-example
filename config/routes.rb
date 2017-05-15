Rails.application.routes.draw do
  root 'home#index'
  
  controller :policy do
    get 'policy', to: "policy#index"
  end
end
