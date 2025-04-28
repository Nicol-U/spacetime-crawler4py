import re
import os
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import hashlib

document_fingerprints = {}
similarity_limit = 0.8


class URLINFO:
    def __init__(self):
        self.url = None
        self.word_count = 0
        self.word_list = {}  # store words that are not stop words

    def set_url(self, url):
        self.url = url

    def set_word_count(self, word_count):
        self.word_count = word_count

    def set_word_list(self, word_list):
        """
        takes word_list which is passed in through createFingerPrint func
        then it calls the function load_stop_words() to get a set of stop words
        then adds non stop words to a dictionary and increments frequcny
        :param word_list:
        :return:
        """
        for word in word_list:
            if word not in load_stop_words():
                if word in self.word_list:
                    self.word_list[word] += 1
                else:
                    self.word_list[word] = 1

    def compare_url_class(self, other):

        pass



longest_Page = [0, ''] # key is number value is url link
tempURL = URLINFO()
currentURL = URLINFO()

def scraper(url, resp):
    """
    Main scraper funtion that processes pages and extracts links
    """
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def load_stop_words():
    """
    Load stop words from file or return empty set if file not found
    """
    try:
        if os.path.exists("stopwords.txt"):
            with open("stopwords.txt", "r") as file:
                return set(line.strip() for line in file if line.strip())
        else:
            print("Warning: stopwords.txt not found")
            return set()
    except Exception as e:
        print(f"Error loading stopwords.txt: {e}")
        return set()

def defrag(url):
    """
    Defragments URL by deleting anything after the #
    """
    fragment_pos = url.find('#')
    if fragment_pos != -1:
        return url[:fragment_pos] # Slices the fragment off
    return url


def createFingerprint(content):
    """
    Creates text fingerprints for near duplicate deletion
    """
    soup = BeautifulSoup(content, 'html.parser') # Gets all html data from page

    for element in soup(['script','style','header','footer','nav']): # Removes any type of text specified here
        element.decompose()

    text = soup.get_text(separator=' ').lower() # Gets text from html and seperates by a space if not already there, making everything lowercase too
    
    text = re.sub(r'\s+', ' ', text).strip() # Replaces sequences of whitespace with 1 space

    n_length = 5 # Length per fingerprint
    words = text.split() # Makes text into individual words for fingerprinting



    # since we have extracted all the words and remvoed html flags it might be best to compare
    # length to any previous word page length and update if needed
    tempURL.set_word_list(content)
    tempURL.set_word_count(len(words))
    # this can be used later for word fequency and other things


    # If too small check
    if len(words) < n_length:
        return set()

    # Makes a set of the ngrams that we will create
    ngrams = set()

    # Creating ngrams, hashing them, and putting them into the set of ngrams for the page
    for i in range(len(words) - n_length + 1):
        ngram = ' '.join(words[i:i+n_length])
        ngram_hash = hashlib.md5(ngram.encode()).hexdigest()
        ngrams.add(ngram_hash)
    
    # Maybe error checks here??

    return ngrams

def nearDupe(content, url):
    # Using createFingerprint to get the fingerprint of the site of interest
    current_fingerprint = createFingerprint(content)

    if len(current_fingerprint) < 10: # Doc too small or fingerprint failed
        return False
    
    # Compares documents and finds the words in common from the fingerprints
    for seenUrl, seenFingerprint in document_fingerprints.items():
        if len(seenFingerprint) > 0:
            intersection = len(current_fingerprint.intersection(seenFingerprint))
            union = len(current_fingerprint.union(seenFingerprint))

            # If union exists, calculate similarity level
            if union > 0:
                similarity = intersection / union
            else:
                similarity = 0
            
            # Similarity checker, returns true if its similar enough
            if similarity >= similarity_limit:
                return True
        
    # If not similar enough store fingerprint for future comparisons and return false
    document_fingerprints[url] = current_fingerprint
    return False

def errorCheck(resp):
    """
    Checks for error conditions in the response
    """
    # When raw_response is none
    if resp.raw_response is None:
        return True

    # Large files
    if len(resp.raw_response.content) > 1000000: #1mb
        print(f"Large file detected: {resp.url}")
        return True

    # Empty files despite 200 code
    if resp.status == 200 and len(resp.raw_response.content) < 100:
        print("Empty content detected: {resp.url}")
        return True

    # Soft 404 aka error page detector in spite of 200 code
    try:
        soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
        title = soup.title.string.lower() if soup.title else ""

        if any(phrase in title for phrase in ["error", "not found", "404"]):
            print("Soft 404 found via keywords: {resp.url}")
            return True

    except Exception as e:
        print("Error analyzing content: {e}")
    
    return False

def calendarUrl(url):
    # Common calendar patterns
    calendar_patterns = [r"tribe-bar-date=\d{4}-\d{2}-\d{2}", r"/events/tag/[^/]+/\d{4}-\d{2}", r"/events/tag/[^/]+/day/\d{4}-\d{2}", r"/events/tag/[^/]+/list/", r"/calendar/"]

    # Returns true if text match patterns
    for pattern in calendar_patterns:
        if re.search(pattern, url):
            print("Calendar URL found: {url}")
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
        print("Skipping calendar URL: {url}")
        return html_Links

    if errorCheck(resp): #returns if error is found, need to add duplicate checking errors
        return html_Links
        
    if nearDupe(resp.raw_response.content, resp.url):
        return html_Links

    if resp.status != 200:
        return html_Links

    if (resp.status == 200):
        parse_html = BeautifulSoup(resp.raw_response.content, 'html.parser')
        links_in_html = parse_html.find_all('a', href=True)
        
        # Extract links
        for link in links_in_html:
            href = link['href']

            # Skip empty links
            if not href or href == "#":
                continue

            # Convert Relative URLs to absolute URLs
            absolute_url = urljoin(resp.url, href)

            # Remove fragment
            defragged_url = defrag(absolute_url)

            html_Links.append(defragged_url)

        return html_Links

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        netloc = parsed.netloc.lower()
        path = parsed.path.lower()

        is_allowed_domain = (
            netloc.endswith(".ics.uci.edu") or
            netloc.endswith(".cs.uci.edu") or
            netloc.endswith(".informatics.uci.edu") or
            netloc.endswith(".stat.uci.edu") or
            (netloc == "today.uci.edu" and path.startswith("/department/information_computer_sciences"))
        )

        if not is_allowed_domain:
            return False

        final_result =  not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

        if final_result:
            # since we determined that this is a valid url then we can add it

            tempURL.set_url(url)
            pass
        #save results from this url for report

        return final_result

    except TypeError:
        print ("TypeError for ", url)
        return False
    except Exception as e:
        print (f"Error validating {url}: e")
        return False




