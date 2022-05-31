# cloudflareViewer
A repo of tools to view Cloudflare API data

Are you a Cloudflare WAF customer? Do you need more from the data than the web page provides? Well I did :) 

This repo uses the Cloudflare API to download data about firewall events and stores it in a sqlite DB. Using Plotext it then creates graphs. 

Hopefully you'll find it useful. I'll be adding new graphs as I need them. 

# Usage

To download data you will need to have an API key and the Zone ID for your Cloudflare environment. Pass these to the program cf-events.py 

    #./cf-events.py  --token=ABC1234  --zoneid=DEF456 

To generate graphs use the command cf-report.py 

    #./cf-report.py --stacked 
    #./cf-report.py --twohour

You can add the option of --interval to specify the time range to query in minutes

    #./cf-report.py --stacked --interval=5 

Do you have multiple zones? You can specify which zone during the storage an retrieval process.

    #./cf-events.py  --token=ABC1234  --zoneid=DEF456  --zonename=example
    #./cf-report.py --twohour --zonename=example

# Advanced Analytics

I had the need to analyze firewall events in a bit more detail. For now you have to run the cf-details.py script to load these details into a sqlite db. 
This will only be of use to some, and the DB grows, so it is broken out into a seperate script for now. 

    ./cf-details.py  --token=ABC1234  --zoneid=DEF456 

    ./cf-report.py --ja3 

    +----------------------------------+-------+-------------+
    |               JA3                | Count | User Agents |
    +----------------------------------+-------+-------------+
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX | 76282 |     3465    |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX | 17061 |     152     |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX | 12670 |     207     |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  7501 |     1142    |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  5306 |      34     |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  3271 |     175     |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  1254 |     212     |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  1115 |      1      |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  1053 |      15     |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  1002 |      8      |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  751  |      1      |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  649  |     393     |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  583  |     148     |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  511  |      15     |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  509  |      3      |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  480  |      75     |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  400  |      10     |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  390  |      64     |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  371  |      37     |
    | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |  308  |      54     |
    +----------------------------------+-------+-------------+ 

This is helpful for me to see JA3 fingerprints with a large number of User Agents, this indicates to me that this is synthetic traffic. 

![alt_tag](https://github.com/joemcmanus/cloudflareViewer/blob/main/img/twohourReport.jpg)
![alt_tag](https://github.com/joemcmanus/cloudflareViewer/blob/main/img/stackedReport.jpg)
![alt_tag](https://github.com/joemcmanus/cloudflareViewer/blob/main/img/ja3.jpg)

