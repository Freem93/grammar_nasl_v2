#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11585);
 script_version ("$Revision: 1.13 $");
 script_cvs_date("$Date: 2016/06/02 14:01:26 $");

 script_osvdb_id(137303);

 script_name(english:"Sambar Server Cleartext Password Transmission");
 script_summary(english:"Makes sure that Sambar runs on top of SSL.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server allows credentials to be transmitted in
cleartext.");
 script_set_attribute(attribute:"description", value:
"The remote Sambar server allows users to log in without using SSL. A
man-in-the-middle attacker can exploit this to capture the passwords
of the users of this server. The attacker can then use these to access
the web mail accounts and modify the web pages on behalf of the users
of the system.");
 script_set_attribute(attribute:"solution", value:
"Use Sambar on top of SSL.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/07");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright("This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencies("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

# The script code starts here
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

user = "whatever";
content = "RCpage=%2Fsysuser%2Fdocmgr%2Fbrowse.stm&onfailure=%2Fsysuser%2Fdocmgr%2Frelogin.htm&path=%2F&RCSsortby=name&RCSbrowse=%2Fsysuser%2Fdocmgr&RCuser=" + user +
"&RCpwd=";

r = http_send_recv3(method: "POST",
                    item: "/session/login",
                    port: port,
                    version: 11,
                    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
                    data: content,
                    exit_on_fail: TRUE);

if (isnull(r) || ereg(pattern:"^HTTP/[0-9]\.[0-9] 404 ", string: r[0]))
  audit(AUDIT_LISTEN_NOT_VULN, "Webserver", port);

if (ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string: r[0]) &&
   "SAMBAR" >< r[0]+r[1]+r[2])
{
    transport = get_port_transport(port);
    if(transport == ENCAPS_IP)
    {
      pci_report = 'The remote Sambar server on port ' + port + ' accepts cleartext logins.';
      set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);
      security_warning(port);
    }
}
else audit(AUDIT_LISTEN_NOT_VULN, "Webserver", port);
