import requests
WEB_PAGE = "https://pixe.la/v1/users/annhabits/graphs/graph1.html"
from datetime import datetime
TOKEN = "gshchjsdzjcvjhsg"
USER_NAME = "annhabits"
pix_endpoint = "https://pixe.la/v1/users"
parameters = {"token": TOKEN, "username": USER_NAME, "agreeTermsOfService": "yes", "notMinor": "yes"}
#response = requests.post(url=pix_endpoint, json=parameters)
#print(response.text)
graph_endpoint = f"{pix_endpoint}/{USER_NAME}/graphs"
graph_config = {"id": "graph1", "name": "Water Graph", "unit": "L", "type": "int", "color": "sora"}
headers = {"X-USER-TOKEN": TOKEN}
#response = requests.post(url=graph_endpoint, json=graph_config, headers=headers)
#print(response.text)
update_endpoint = f"{pix_endpoint}/{USER_NAME}/graphs/{graph_config["id"]}"
today = datetime.now()
#liters = str(random.randint(1, 20))
tracker_data = {"date": today.strftime("%Y%m%d"), "quantity": input("how many litres of water did you drink?")}
response = requests.post(url=update_endpoint, json=tracker_data, headers=headers)
print(response.text)
