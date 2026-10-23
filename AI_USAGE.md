# AI usage: dsc26-cyb-w02

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools
I used only ChatGPT. I used it to understand the task itself at the beginning because I was having a rough time understanding it. Then, I used it to write the core.py file, add threats to the YAML file, and edit part of main.py. Also at the end, I needed to make sure that all requirments were met and done correctly "checking".

## What AI got wrong
ChatGPT actually got two parts wrong.

It used the wrong protocol. It was supposed to be mtls, but it used tls.

In core.py, in the validate() function, the function was written in a way that made the test produce no issues at all. But then, when I compared what I had done with the hidden test section, I found something missing, which was the "kind" part. So, I fixed it and tested again. It produced issues, so I added more threats and fixed them until no issues were reported.

## In my own words

1. Why does a data store have no Spoofing threats in STRIDE per element, and where does that threat go instead?
There can't be Spoofing in a data store. Spoofing means impersonating someone to access the data store. The data store itself cannot be spoofed, so the Spoofing threat applies to a person, which means the threat goes to the user (entity) or a trusted service.

2. Which of your eleven new threats would you fix first, and why that one?
I think T34, "Unauthorized Modification of Stored Case Records." I think tampering with data is very dangerous and can lead to the company being sued and ruin its reputation.