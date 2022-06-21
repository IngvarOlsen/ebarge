import requests

# Examples of Restfull API data call from python
# Part of the school project

api_url = "http://20.238.120.222:5000/reading_post"
stringToSend = "testerStringData"
jsonToSend = {"userId": 1, "title": "Wash car", "completed": True}
responseData = requests.post(api_url + "_data", stringToSend)
print(responseData.status_code)

responseJson = requests.post(api_url + "_json", json=jsonToSend)
print(responseJson.status_code)

