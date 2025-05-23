import re
import os
from itertools import islice
from logging import exception
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import hashlib

document_fingerprints = {}
similarity_limit = 0.9
document_checksums = set()
unique_urls = set()

uci_edu_sub_domians = {}
# A dict of subdomains and count of unique pages

class URLINFO:
    """
    store info related to urls in a temp and main instance to compare later
    and use to update main version might need to
    """
    def __init__(self):
        self.url = None
        self.word_count = 0
        self.word_list = {}  # Store words that are not stop words

    def set_url(self, url):
        self.url = url

    def check_word(self, word):
        """
        get ride of single letters and only allow words not number to go through
        """

        if word.isdigit() or len(word) < 2:
            return False

        for char in word:
            if not char.isalpha():
                return False

        return True
        
    def set_word_list(self, word_list):
        """
        takes word_list which is passed in through createFingerPrint func
        then it calls the function load_stop_words() to get a set of stop words
        then adds non stop words to a dictionary and increments frequcny
        :param word_list:
        :return:
        """
        try:
            for word in word_list:
                if self.check_word(word) and word not in load_stop_words():
                    if word in self.word_list:
                        self.word_list[word] += 1

                    else:
                        self.word_list[word] = 1

                    self.word_count += 1

        except Exception as e:
            print(f"line 32 Exception occured {e}")

    def update_when_better(self, other):
        """
        other = tempURL and this will update MainURL
        for largest page count and which url it came from.
        :param other:
        :return:
        """
        if self.word_count < other.word_count:
            self.word_count = other.word_count
            self.url = other.url

    def update_word_list(self, other):
        """
        given another class instance, it adds any new frequcies and
        increments current values
        then sorts the it
        this is ment to be called on MainURL with peram being temp
        :param other:
        :return:
        """
        try:
            for word in other.word_list:

                if word in self.word_list:
                    self.word_list[word] += other.word_list[word]
                else:
                    self.word_list[word] = other.word_list[word]
            self.word_list = dict(sorted(self.word_list.items(), key=lambda item: item[1], reverse=True))
        except Exception as e:
            print(f"line 58: {e}\n")

    def get_largest_url(self):
        try:
            return self.url, self.word_count
        except Exception as e:
            print(f"line 74 Exception: {e}\n")

    def get_word_frequency(self):
        try:
            """returns a list that is 50 items long"""
            if len(self.word_list) <= 50:
                return self.word_list
            else:
                return dict(islice(self.word_list.items(), 50))
        except Exception as e:
            print(f"get_word_frequency line 76 Exception: {e}")

MainURL = URLINFO()

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

def createFingerprint(content, url):
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
    temp_url = URLINFO()
    temp_url.set_url(url)
    temp_url.set_word_list(words)
    # this can be used later for word fequency and other things

    #set main url
    MainURL.update_word_list(temp_url)
    MainURL.update_when_better(temp_url)

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

#checks for exact duplicates to existing websites
def exactDupe(content):
    #creates hash of current site text
    current_hash = hashlib.md5(content).hexdigest()

    #checks doc against other hashes created and looks for a match, returning True if match found
    if current_hash in document_checksums:
        print(f"Exact dupe detected. Hash: {current_hash}")
        return True
    
    #if not found add to list of unique websites
    document_checksums.add(current_hash)

    return False

def nearDupe(content, url):
    # Using createFingerprint to get the fingerprint of the site of interest
    current_fingerprint = createFingerprint(content, url)

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

def imageWordRatio(resp):
    try:
        soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
        
        # image count
        images = soup.find_all('img')
        image_count = len(images)
        
        # Get text
        text = soup.get_text(separator=' ')
        text = re.sub(r'\s+', ' ', text).strip()
        words = text.split()
        word_count = len(words)
        
        # Image check
        if image_count > 0 and word_count / image_count < 20:  # filter out if < 20 words per image
            return True
            
        return False

    except Exception as e:
        print(f"Error in image heavy check: {e}")
        return False

def errorCheck(resp):
    """
    Checks for error conditions in the response
    """
    # When raw_response is none
    if resp.raw_response is None:
        return True

    # Large files
    if len(resp.raw_response.content) > 2500000: #2.5mb
        print(f"Large file detected: {resp.url}")
        return True

    # Empty or very small (low info value) files despite 200 code
    if resp.status == 200 and len(resp.raw_response.content) < 400:
        print(f"Empty content detected: {resp.url}")
        return True

    # Soft 404 aka error page detector in spite of 200 code
    try:
        soup = BeautifulSoup(resp.raw_response.content, 'html.parser')

        title = soup.title.string.lower() if soup.title else ""

        if any(phrase in title for phrase in ["error", "not found", "404", "forbidden", "access denied",
        "not authorized", "maintenance", "temporarily unavailable", "under construction", "coming soon",
        "apache", "nginx", "server error", "403", "401", "500"]):
            print(f"Soft 404 found via keywords: {resp.url}")
            return True

    except Exception as e:
        print(f"Error analyzing content: {e}")
    
    return False

def calendarUrl(url):
    # Common calendar patterns
    calendar_patterns = [r"tribe-bar-date=\d{4}-\d{2}-\d{2}", r"/events/tag/[^/]+/\d{4}-\d{2}", r"/events/tag/[^/]+/day/\d{4}-\d{2}", r"/events/tag/[^/]+/list/", r"/calendar/"]

    # Returns true if text match patterns
    for pattern in calendar_patterns:
        if re.search(pattern, url):
            print(f"Calendar URL found: {url}")
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

    html_links = []

    #check for calendar urls and skip them because they lead to infinite trap
    if calendarUrl(url):
        print(f"Skipping calendar URL: {url}")
        return html_links

    if errorCheck(resp): #returns if error is found, need to add duplicate checking errors
        return html_links

    if imageWordRatio(resp):
        return html_links
        
    if exactDupe(resp.raw_response.content):
        print(f"Skipping exact dupe: {resp.url}")
        return html_links

    if nearDupe(resp.raw_response.content, resp.url):
        print(f"Skipping near dupe: {resp.url}")
        return html_links

    if resp.status != 200:
        return html_links

    if (resp.status == 200):
        parse_html = BeautifulSoup(resp.raw_response.content, 'html.parser')
        links_in_html = parse_html.find_all('a', href=True)

    if (resp.status == 200):
        defragged_url = defrag(resp.url)
        unique_urls.add(defragged_url)  # adds current url to unique set to correctly count number of unique pages by definition in assignment (by url) rather than by unique content
        
        # Extract links
        for link in links_in_html:
            href = link['href']

            # Skip empty links
            if not href or href == "#":
                continue

            placeholder_patterns = ['YOUR_IP', 'YOUR_DOMAIN', 'YOUR_USERNAME', 'YOUR_PASSWORD']
            if any(pattern in href for pattern in placeholder_patterns):
                print(f"skipping placeholder URL trap: {href}")
                continue
            
            try:
                # Convert Relative URLs to absolute URLs
                absolute_url = urljoin(resp.url, href)

                # Remove fragment
                defragged_url = defrag(absolute_url)

                html_links.append(defragged_url)

            except Exception as e:
                print(f"Error parsing URL {href}: {e}")
                continue

        return html_links

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        # blocking specific traps
        if "doku" in url.lower(): #doku trap handling
            return False

        # if "eppstein" in url.lower(): #eppstein trap handling
        #     return False

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

        final_result = not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

        if final_result:
            #I commented them out since they are already done on line 395 and 396
            #parsed = urlparse(url)
            #netloc = parsed.netloc.lower()

            if netloc not in uci_edu_sub_domians:
                uci_edu_sub_domians[netloc] = set()

            uci_edu_sub_domians[netloc].add(path)

        return final_result

    except TypeError:
        print (f"TypeError for {url}")
        return False
    except Exception as e:
        print (f"Error validating {url}: {e}")
        return False

def write_URL_Report():
    """this should make and write to the file i added a try and except in general
    just incase to keep the crawel from crashing since this is untested"""

    total_unique_pages = len(unique_urls)
    try:
        with open('Report.txt', 'w') as f:
            # longest url and the number of words
            f.write(f"longest page {MainURL.get_largest_url()[0]} word count {MainURL.get_largest_url()[1]}\n")
            f.write("-"*20 + "\n")

            #top 50 words with their number
            f.write("Top 50 most common words:\n")
            word_count = 0
            for word, number in MainURL.get_word_frequency().items():
                if word_count < 50:
                    f.write(f"{word} ---> {number}\n")
                    word_count += 1
                else:
                    break
            f.write("-"*20 + "\n")

            #this should get the subdomains sort them and iterate through subdomain and page count
            f.write(f"subdomain & unique pages counts: \n")
            for subdomain, count in sorted(uci_edu_sub_domians.items()):
                f.write(f"{subdomain} ---> {len(count)}\n")
            
            f.write("-"*20 + "\n")

            # writes total # of unique pages
            f.write(f"Total unique pages count:\n")
            f.write(str(total_unique_pages))

        #call func that prints raw report info
        just_in_Case()
    except Exception as e:
        print(f"Error writing to Report.txt: {e}")


def just_in_Case():
    """
    write's all the raw data to a file doesn't have totals or numbers
    just the urls, pages and words gathered through the crawl.
    By words I mean all words not just 50. we can always write code to filter
    this info again later
    :return:
    """
    try:
        with open('Just_IN_Case_RawReport.txt', 'w') as f:
            #this should still be the same
            f.write(f"longest page {MainURL.get_largest_url()[0]} word count {MainURL.get_largest_url()[1]}\n")
            f.write("-" * 20 + "\n")

            #all words not jsut hte top 50
            f.write("All words and there count\n")
            # we can later split by : if needed to re-read them
            for word, number in MainURL.word_list.items():
                f.write(f"{word}:{number}\n")
            f.write("-" * 20 + "\n")

            # writes subdomains and the pages not the number but the page name
            f.write(f"subdomain & unique pages counts: \n")
            for subdomain, PageSet in sorted(uci_edu_sub_domians.items()):
                f.write(f"{subdomain}:")
                for page in PageSet:
                    f.write(f"{page},")
                f.write("\n")
            f.write("-" * 20 + "\n")

        # write all the pages from carl's unique url set
        # Maybe not needed since unique pages adds up to/has the
        # same elements as the function above
        """    f.write(f"ALL unique pages:\n")
            for elem in unique_urls:
                f.write(f"{elem}\n")
            f.write("-" * 20 + "\n")
            
        """


    except Exception as e:
        print(f"Error writing to RawReport.txt: {e}")





