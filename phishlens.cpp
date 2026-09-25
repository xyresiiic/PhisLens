#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

string toLower(string s) {
  for (int i = 0; i < (int)s.size(); i++)
    s[i] = tolower(s[i]);
  return s;
}

bool contains(string text, string word) {
  return text.find(word) != string::npos;
}

string knownBrands[] = {"paypal", "google", "amazon", "microsoft", "netflix"};
int knownBrandsCount = 5;

string suspiciousTlds[] = {".xyz", ".top", ".tk", ".click", ".info"};
int suspiciousTldsCount = 5;

string shorteners[] = {"bit.ly", "tinyurl.com", "t.co"};
int shortenersCount = 3;

string urgencyWords[] = {"verify your account", "act now",
                         "suspended",           "click here",
                         "final notice",        "unusual activity",
                         "confirm",             "action needed"};
int urgencyWordsCount = 8;

string credentialWords[] = {"enter your password", "login to verify",
                            "confirm your ssn", "otp", "password",
                            "login", "confirm"};
int credentialWordsCount = 7;

struct Evidence {
  string category;
  string reason;
  int points;
};

const int MAX_EVIDENCE = 50;
Evidence evidenceList[MAX_EVIDENCE];
int evidenceCount = 0;

void addEvidence(string category, string reason, int points) {
  if (evidenceCount < MAX_EVIDENCE) {
    evidenceList[evidenceCount].category = category;
    evidenceList[evidenceCount].reason = reason;
    evidenceList[evidenceCount].points = points;
    evidenceCount++;
  }
}

// get the domain part after "@"

string getDomain(string from) {
  int at = from.find('@');
  if (at == -1)
    return "";
  int end = from.find('>', at);
  if (end == -1)
    end = from.size();
  return toLower(from.substr(at + 1, end - at - 1));
}

// check sender name aur domain
void checkSender(string from, string replyTo) {
  string fromLower = toLower(from);
  string fromDomain = getDomain(from);

  for (int i = 0; i < knownBrandsCount; i++) {
    string brand = knownBrands[i];
    if (contains(fromLower, brand) && !contains(fromDomain, brand)) {
      addEvidence("Sender",
                  "Claims to be \"" + brand + "\" but domain is \"" +
                      fromDomain + "\"",
                  20);
    }
  }

  // kya reply domain alag hai?
  if (replyTo != "") {
    string replyDomain = getDomain(replyTo);
    if (replyDomain != "" && replyDomain != fromDomain) {
      addEvidence("Sender",
                  "Reply-To domain (" + replyDomain +
                      ") does not match From domain",
                  15);
    }
  }
}

// link check
void checkLinks(string body) {
  string bodyLower = toLower(body);

  if (contains(bodyLower, "http://")) {
    int pos = bodyLower.find("http://") + 7;
    if (pos < (int)bodyLower.size() && isdigit(bodyLower[pos])) {
      addEvidence("URL", "Link uses a raw IP address instead of a real domain",
                  20);
    }
  }

  bool loginRelatedLink = false;
  string loginTerms[] = {"login", "verify", "account", "update", "confirm"};
  for (int i = 0; i < 5; i++) {
    if (contains(bodyLower, loginTerms[i])) {
      loginRelatedLink = true;
      break;
    }
  }

  if (loginRelatedLink && contains(bodyLower, "https://")) {
    addEvidence("URL", "Login/update action is linked in the email body", 10);
  }

  for (int i = 0; i < suspiciousTldsCount; i++) {
    if (contains(bodyLower, suspiciousTlds[i]))
      addEvidence("URL",
                  "Link uses a risky domain ending (" + suspiciousTlds[i] + ")",
                  20);
  }

  for (int i = 0; i < shortenersCount; i++) {
    if (contains(bodyLower, shorteners[i]))
      addEvidence("URL",
                  "Link is shortened (" + shorteners[i] +
                      ") and hides its real target",
                  10);
  }
}

// check for urgent language(like koi credential stealing)
void checkContent(string body) {
  string bodyLower = toLower(body);

  vector<string> urgencyMatches;
  for (int i = 0; i < urgencyWordsCount; i++) {
    if (contains(bodyLower, urgencyWords[i]))
      urgencyMatches.push_back(urgencyWords[i]);
  }
  if (!urgencyMatches.empty()) {
    string detail = urgencyMatches[0];
    for (size_t i = 1; i < urgencyMatches.size(); i++)
      detail += ", " + urgencyMatches[i];
    addEvidence("Content",
                "Urgent/pressure phrase found: \"" + detail + "\"",
                10);
  }

  vector<string> credentialMatches;
  for (int i = 0; i < credentialWordsCount; i++) {
    if (contains(bodyLower, credentialWords[i]))
      credentialMatches.push_back(credentialWords[i]);
  }
  if (!credentialMatches.empty()) {
    string detail = credentialMatches[0];
    for (size_t i = 1; i < credentialMatches.size(); i++)
      detail += ", " + credentialMatches[i];
    addEvidence("Content",
                "Credential-stealing phrase found: \"" + detail + "\"",
                10);
  }
}

void checkAuth(string authLine) {
  string a = toLower(authLine);
  if (contains(a, "spf=fail"))
    addEvidence("Auth", "SPF check failed", 15);
  if (contains(a, "dkim=fail") || contains(a, "dkim=none"))
    addEvidence("Auth", "DKIM check failed", 15);
  if (contains(a, "dmarc=fail"))
    addEvidence("Auth", "DMARC check failed", 15);
}

string resolveInputFile(string name) {
  if (name.empty())
    return "";

  ifstream direct(name.c_str());
  if (direct.good())
    return name;

  string candidates[] = {"public/samples/" + name, "samples/" + name,
                        "./" + name};

  for (int i = 0; i < 3; i++) {
    ifstream test(candidates[i].c_str());
    if (test.good())
      return candidates[i];
  }

  return name;
}

int main(int argc, char *argv[]) {
  string from, replyTo, authLine, subject, body;
  string fileName;

  if (argc >= 2) {
    fileName = argv[1];
  } else {
    cout << "Enter File to check: ";
    getline(cin, fileName);
  }

  fileName = resolveInputFile(fileName);

  if (!fileName.empty()) {
    ifstream file(fileName.c_str());
    if (!file) {
      cout << "Could not open file: " << fileName << endl;
      return 1;
    }
    string line;
    bool inBody = false;
    while (getline(file, line)) {
      if (line == "" || line == "\r") {
        inBody = true;
        continue;
      }
      if (!inBody) {
        if (line.substr(0, 5) == "From:")
          from = line.substr(5);
        else if (line.substr(0, 9) == "Reply-To:")
          replyTo = line.substr(9);
        else if (line.substr(0, 8) == "Subject:")
          subject = line.substr(8);
        else if (line.substr(0, 23) == "Authentication-Results:")
          authLine = line.substr(23);
      } else {
        body += line + "\n";
      }
    }
  } else {
    // built-in demo email if no file is given
    cout << "No file given, running demo sample. (Usage: ./phislens "
            "email.eml)\n\n";
    from = " \"PayPal Security\" <alert@paypa1.xyz>";
    replyTo = " support@different-domain.top";
    subject = " Urgent: verify your account";
    authLine = " spf=fail dkim=none dmarc=fail";
    body = "Your account will be suspended. Click here immediately: "
           "http://192.168.1.5/login. Please login to verify and enter your "
           "password.\n";
  }

  checkSender(from, replyTo);
  checkLinks(body);
  checkContent(body);
  checkAuth(authLine);

  // add up all points, max 100
  int score = 0;
  for (int i = 0; i < evidenceCount; i++)
    score += evidenceList[i].points;
  if (score > 100)
    score = 100;

  string verdict;
  if (score >= 60)
    verdict = "PHISHING";
  else if (score >= 25)
    verdict = "SUSPICIOUS";
  else
    verdict = "LEGITIMATE";

  // print the report
  cout << "==================================================\n";
  cout << " PhisLens Report\n";
  cout << "==================================================\n";
  cout << "From: " << from << endl;
  cout << "Subject: " << subject << endl;
  cout << "--------------------------------------------------\n";
  cout << "Risk Score: " << score << " / 100\n";
  cout << "Verdict: " << verdict << endl;
  cout << "--------------------------------------------------\n";

  if (evidenceCount == 0) {
    cout << "No suspicious signs found.\n";
  } else {
    cout << "Evidence found:\n";
    for (int i = 0; i < evidenceCount; i++) {
      cout << "  [+" << evidenceList[i].points << "] ("
           << evidenceList[i].category << ") " << evidenceList[i].reason
           << endl;
    }
  }
  cout << "==================================================\n";

  return 0;
}