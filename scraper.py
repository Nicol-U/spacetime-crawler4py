import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import hashlib

documentFingerprints = {}
similarityLimit = .8

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

#defragments a url by deleting anything after the #, if there is no fragment it does nothing
def defrag(url):
    fragmentPos = url.find('#')

    if fragmentPos != -1:
        return url[:fragmentPos] #slices the fragment off

    return url

#creates fingerprints for the text
def createFingerprint(content):
    soup = BeautifulSoup(content, 'html.parser') #gets all html data from page

    for element in soup(['script','style','header','footer','nav']): #removes any type of text specified here
        element.decompose()

    text = soup.get_text(separator=' ').lower() #gets text from html and seperates by a space if not already there, making everything lowercase too
    
    text = re.sub(r'\s+', ' ', text).strip() # replaces sequences of whitespace with 1 space

    n_length = 5 #length per fingerprint
    words = text.split() #makes text into individual words for fingerprinting

    #if too small check
    if len(words) < n_length:
        return set()

    #makes a set of the ngrams that we will create
    ngrams = set()

    #creating ngrams, hashing them, and putting them into the set of ngrams for the page
    for i in range(len(words) - n_length + 1):
        ngram = ' '.join(words[i:i+n_length])
        ngram_hash = hashlib.md5(ngram.encode()).hexdigest()
        ngrams.add(ngram_hash)
    
    #maybe error checks here??

    return ngrams

def nearDupe(content, url):
    #using createFingerprint to get the fingerprint of the site of interest
    currentFingerprint = createFingerprint(content)

    if len(currentFingerprint) < 10: #doc too small or fingerprint failed
        return False
    
    #compares documents and finds the words in common from the fingerprints
    for seenUrl, seenFingerprint in documentFingerprints.items():
        if len(seenFingerprint) > 0:
            intersection = len(currentFingerprint.intersection(seenFingerprint))
            union = len(currentFingerprint.union(seenFingerprint))

            #if union exists, calculate similarity level
            if union > 0:
                similarity = intersection / union
            else:
                similarity = 0
            
            #similarity checker, returns true if its similar enough
            if similarity >= similarityLimit:
                return True
        
    #if not similar enough store fingerprint for future comparisons and return false
    documentFingerprints[url] = currentFingerprint
    return False

def errorCheck(resp):

    #large files
    if len(resp.raw_response.content) > 1000000: #1mb
        print("Large file detected: %s" % resp.url)
        return True

    #empty files despite 200 code
    if resp.status == 200 and len(resp.raw_response.content) < 100:
        print("Empty content detected: %s" % resp.url)
        return True

    #soft 404 aka error page detector in spite of 200 code
    try:
        soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
        title = soup.title.string.lower() if soup.title else ""

        if any(phrase in title for phrase in ["error", "not found", "404"]):
            print("Soft 404 found via keywords: %s" % resp.url)
            return True

    except Exception as e:
        print("Error analyzing content: %s" % e)
    
    return False

def calendarUrl(url):
    #common calendar patterns
    calendarPatterns = [r"tribe-bar-date=\d{4}-\d{2}-\d{2}", r"/events/tag/[^/]+/\d{4}-\d{2}", r"/events/tag/[^/]+/day/\d{4}-\d{2}", r"/events/tag/[^/]+/list/", r"/calendar/"]

    #returns true if text match patterns
    for pattern in calendarPatterns:
        if re.search(pattern, url):
            print("Calendar URL found: %s" % url)
            return True
        
    return False


#Implement exact and near webpage similarity detection using the methods discussed in the lecture. Your implementation must be made from scratch, no libraries are allowed.

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content

    html_Links = []

    #check for calendar urls and skip them because they lead to infinite trap
    if calendarUrl(url):
        print("Skipping calendar URL: %s" % url)
        return html_Links

    if errorCheck(resp): #returns if error is found, need to add duplicate checking errors
        return html_Links
        
    if nearDupe(resp.raw_response.content, resp.url):
        return html_Links

    if resp.status != 200:
        return html_Links

    if (resp.status == 200):
        ParseHTML = BeautifulSoup(resp.raw_response.content, 'html.parser')
        lnksInHTML = ParseHTML.find_all('a', href=True)
        for link in lnksInHTML:
            #print(link['href']) #delete or change to see what it does
            defraggedUrl = defrag(link['href'])

            html_Links.append(defraggedUrl)

        return html_Links

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        endswith =  not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())
        containsICS = re.search("ics.uci.edu|cs.uci.edu|"
                                + ".informatics.uci.edu|.stat.uci.edu"
                                + "today.uci.edu/department/information_computer_sciences/",
                                parsed.netloc.lower()) #parsed.path.lower() was og, terminates weird but seems to traverse well
        #print(endswith and containsICS)
        #print(url)
        return endswith and containsICS
    except TypeError:
        print ("TypeError for ", parsed)
        raise