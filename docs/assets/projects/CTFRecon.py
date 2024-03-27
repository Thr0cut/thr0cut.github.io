import argparse
import subprocess
import os
import requests
from time import sleep
from pathlib import Path
from colorama import Fore, Back, Style


def get_arguments():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    # Subparser for "new" run mode

    new_parser = subparsers.add_parser('new', help='Perform basic recon for a new CTF')
    new_parser.add_argument('-n', help='CTF name')
    new_parser.add_argument('-ip', help='IP address')

    # Subparser for "delete" run mode

    delete_parser = subparsers.add_parser('delete', help='Delete entries for a previously played CTF')
    delete_parser.add_argument('-n', help='CTF name')

    # Parse the command line arguments
    args = parser.parse_args()
    return args

def new_ctf(n, ip):
    # Get home directory of the user running the tool with SUDO from SUDO_USER environment variable
    userhome = os.environ['SUDO_USER']
    # Command to add an entry to /etc/hosts file
    hostname_command = f"echo '{ip} {n}.htb' >> /etc/hosts"
    # Specify /dev/null path (for input/output/error handling
    DEVNULL = open(os.devnull, 'wb')

    print('\nCTFRecon.py by Thr0cut - Basic Reconnaissance For HackTheBox')
    sleep(1)
    print(f'\n[+] Starting reconnaissance for CTF {Fore.RED}{Style.BRIGHT}"{n.title()}"{Style.RESET_ALL} with machine IP {Fore.RED}{Style.BRIGHT}{ip}{Style.RESET_ALL}. '
          f'Go grab some coffee, sit back and relax! ;)')

    sleep(2)
    # Start a loop for command execution (prevent the program from exiting in case of incorrect input / exceptions)
    while True:
        try:
            # Specify path for a new CTF directory
            path = Path(f'/home/{userhome}/CTFs/{n.title()}')
            # Create directory
            Path(path).mkdir(parents=True, exist_ok=False)
            sleep(2)
            print("\n[+] Created directory " + f"{Fore.RED}{Style.BRIGHT}{path}{Style.RESET_ALL}")
            # Add a host entry to /etc/hosts file
            subprocess.run(hostname_command, shell=True)
            sleep(2)
            print(f"\n[+] Added entry {Fore.RED}{Style.BRIGHT}'{ip} {n}.htb'{Style.RESET_ALL} to /etc/hosts file.")
            sleep(2)
            # If webserver is up, get its URL from check_webserver function
            webserver = check_webserver(n)
            # If webserver URL is returned, run command batch_1 (w/ directory enumeration, else run batch_2 (w/o directory enumeration)
            if webserver:

                batch_1 = ["nmap -sC -sV -T4 " + f"{ip} " + f"-oN {path}/nmap_results.txt",
                           "ffuf -H " + f"'Host: FUZZ.{n}.htb' " +
                           f'-w /usr/share/wordlists/amass/subdomains-top1mil-20000.txt -t 50 -s -o ' +
                           f'{path}/ffuf-results.txt ' + f"-u {webserver} -ac -or " +
                           "&& cat ffuf-results.txt | jq -c '.results[] | {STTS: .status, HOST: .host}' > ffuf_results.txt && rm ffuf-results.txt",
                           "dirsearch -u " + f"{webserver} " + f"-r -R 2 -e php -o {path}/dirsearch_results.txt"]

                print((f"\n[+] Enumerating the target with the following tools / options:"
                       f"\n\n{Fore.CYAN}{Style.BRIGHT}Nmap: {Style.RESET_ALL}{batch_1[0]}"
                       f"\n{Fore.CYAN}{Style.BRIGHT}Dirsearch: {Style.RESET_ALL}{batch_1[2]}"
                       f"\n{Fore.CYAN}{Style.BRIGHT}Fuff: {Style.RESET_ALL}{batch_1[1]}"
                       f"\n\n[+] Reconnaissance status: "), end='')

                for command in batch_1:
                    # Run commands as parallel processes, redirect stdin, stderr and stdout to /dev/null (won't affect command output file, which is hardcoded)
                    command = subprocess.Popen(command, shell=True, stdin=DEVNULL, stderr=DEVNULL, stdout=DEVNULL)
                    command.wait()

                print(f"{Fore.GREEN}{Style.BRIGHT}Completed{Style.RESET_ALL}.")

            else:

                batch_2 = ["nmap -sC -sV -T4 " + f"{ip} " + f"-oN {path}/nmap_results.txt"]

                print((f"\n[+] Enumerating the target with the following tools / options: "
                       f"\n\n{Fore.CYAN}{Style.BRIGHT}Nmap: {Style.RESET_ALL}{batch_2[0]}"
                       f"\n{Fore.CYAN}{Style.BRIGHT}Dirsearch: {Style.RESET_ALL}Skipping directory enumeration, webserver not found."
                       f"\n{Fore.CYAN}{Style.BRIGHT}Fuff: {Style.RESET_ALL}Skipping subdomain enumeration, webserver not found."
                       f"\n\n[+] Reconnaissance status: "), end='')

                for command in batch_2:
                    # Run commands as parallel processes, redirect stdin, stderr and stdout to /dev/null (won't affect command output file, which is hardcoded)
                    command = subprocess.Popen(command, shell=True, stdin=DEVNULL, stderr=DEVNULL, stdout=DEVNULL)
                    command.wait()

                print(f"{Fore.GREEN}{Style.BRIGHT}Completed{Style.RESET_ALL}.")



            print(f"\n[+] Basic reconnaissance for {Fore.RED}{Style.BRIGHT}{n.title()} {ip}{Style.RESET_ALL} has been completed,"
                  f" check {Fore.RED}{Style.BRIGHT}{path}{Style.RESET_ALL} for results!")
            break

        except KeyboardInterrupt:
            print("\nKeyboard interrupt, exiting.")
            exit()

        # If directory with entered name already exists, keep requesting a new name:
        except FileExistsError:
            try:
                n = input(f'Directory for CTF {Fore.RED}{Style.BRIGHT}"{n.title()}"{Style.RESET_ALL} already exists, please enter a new name: ')
                continue
            # Nested KeyboardInterrupt for a smoother exit while in FileExistsError exception
            except KeyboardInterrupt:
                print("\nKeyboard interrupt, exiting.")
                exit()

def check_webserver(n):
    # Define possible webserver URLs w/ common ports
    host_list = [f'http://{n}.htb:80', f'http://{n}.htb:8080']
    # Send requests to URLs from the list. If a response is received, webserver URL is returned to be used for Dirsearch enumeration
    for webserver in host_list:
        try:
            resp = requests.get(webserver)
            if resp:
                return(webserver)

        # Handle (skip) ConnectionError exception
        except requests.exceptions.ConnectionError:
            pass

def delete_ctf(n):
    # Get home directory of the user running the tool with SUDO from SUDO_USER environment variable
    userhome = os.environ['SUDO_USER']
    # Specify path to requested CTF directory.
    path = Path(f"/home/{userhome}/CTFs/{n.title()}")
    check_path = Path(path)
    # If CTF directory exists, delete it with its contents as well as a corresponding entry in /etc/hosts file
    if check_path.exists():
        sleep(2)
        print(f'\n\r[+] Deleting CTF {Fore.RED}{Style.BRIGHT}"{n.title()}"{Style.RESET_ALL} files and a corresponding entry in /etc/hosts file...', end=' ')
        try:
            subprocess.run(["rm", "-rf", f"{path}"], check=True)
            subprocess.run(["sed", "-i", f'/{n}.htb/d', "/etc/hosts"], check=True)
        except subprocess.CalledProcessError:
            print(f"{Fore.RED}{Style.BRIGHT}Failed{Style.RESET_ALL}.")
            exit(1)
        sleep(2)
        print(f"{Fore.GREEN}{Style.BRIGHT}Completed.")
    else:
        print(f'\nUnable to find CTF {Fore.RED}{Style.BRIGHT}"{n.title()}"{Style.RESET_ALL}, mind checking the name?')

def run_script():
    # Import user arguments from get_arguments function
    args = get_arguments()
    # Check if the tool is run with SUDO (required for modifying /etc/hosts and some tools), exit if ran w/o SUDO
    check_sudo = os.getuid()
    if check_sudo != 0:
        print("Please run the script with SUDO privileges!")
        exit()
    # Check if required arguments have been supplied, run the script if yes
    if args.command == 'new':
        if args.n == None:
            print("Provide CTF name with '-n' flag!")
        elif args.ip == None:
            print("Provide target IP address with '-ip' flag!")
        # Forcing argument formatting for n.lower() for better naming convention handling
        else:
            new_ctf(args.n.lower(), args.ip)

    elif args.command == 'delete':
        if args.n == None:
            print("Provide CTF name with '-n' flag!")
        # Forcing argument formatting for n.lower() for better naming convention handling
        else:
            delete_ctf(args.n.lower())

    elif args.command == None:
        print("No run mode provided, run the script with '-h' flag to list available run modes!")

if __name__ == "__main__":
    run_script()
