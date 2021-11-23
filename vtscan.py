#requirement : pip3 install vt, hashlib
import vt
import hashlib
import readline

#Enter your VirusTotal API key
client = vt.Client("")

print("------------------------------------------------\n")
print("                   VT Scan                      \n")
print("Author                                      Date\n"+
      "SkallZou                                    2021\n"+
      "------------------------------------------------\n")

print("What do you want to do ?\n")
print("1. Check file")
print("2. Check URL")
choice = input()

if choice == "1":
    print("---------------------------------------\n" +
          "               CHECK FILE              \n" +
          "---------------------------------------")
    #to make tabulation complete
    readline.set_completer_delims(' \t\n=')
    readline.parse_and_bind("tab: complete")
    file_path = input("Please indicate the file path: ")
    file_md5 = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
    file_to_analyze = client.get_object("/files/{}", format(file_md5))
    file_analyzed = file_to_analyze.last_analysis_stats
    print("Suspicious: " + str(file_analyzed.get("suspicious")) +
          "\nMalicious: " + str(file_analyzed.get("malicious")) +
          "\nFail: " + str(file_analyzed.get("failure")) +   
          "\nUndetected : " + str(file_analyzed.get("undetected")))


elif choice == "2":
    print("---------------------------------------\n" +
          "                CHECK URL              \n" +
          "---------------------------------------")

client.close()
                                