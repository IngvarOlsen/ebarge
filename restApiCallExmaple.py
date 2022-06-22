import requests

# Examples of Restfull API data call from python
# Part of the school project

api_url = "http://20.238.120.222:5000/reading_post"
stringToSend1 = "2,22,44,33,4.9"
stringToSend2 = "3,29,49,59,4.9"
jsonToSend = {"userId": 1, "title": "Wash car", "completed": True}
responseData1 = requests.post(api_url + "_data", stringToSend1)
print(responseData1.status_code)
responseData2 = requests.post(api_url + "_data", stringToSend2)
print(responseData2.status_code)


#responseJson = requests.post(api_url + "_json", json=jsonToSend)
#print(responseJson.status_code)

