#
# (C) Tenable NetworkSecurity, Inc.
#

include("compat.inc");

if(description)
{
  script_id(42833);
  script_version ("$Revision: 1.5 $");

  script_cve_id("CVE-2004-1892");
  script_bugtraq_id(10039);
  script_osvdb_id(4937);
 
  script_name(english:"eMule IRC Module / Web Server DecodeBase16 Function Remote Overflow");
  script_summary(english:"Checks version saved in the KB");
 
  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on this host." );
  script_set_attribute(attribute:"description", value:
"According to its version, the eMule Web Server listening on this port
contains a buffer overflow vulnerability in the 'DecodeBase16'
function due to a lack of length checks on its inputs.  An anonymous
remote attacker may be able to leverage this issue to execute
arbitrary code on the affected host." );
  script_set_attribute(attribute:"see_also", value:"http://security.nnov.ru/search/news.asp?binid=3572" );
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=108100987429960&w=2" );
  script_set_attribute(attribute:"solution", value:
"Either upgrade to eMule version 0.42e or later, do not use the eMule
web server and IRC client, or uninstall eMule." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/11/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/04/05");
 script_cvs_date("$Date: 2011/03/21 16:24:55 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc."); 
  script_family(english:"Peer-To-Peer File Sharing");
  script_dependencies("eMuleWebServer_detect.nasl");
  script_require_ports("Services/www", 4711);
  exit(0);
}

include("global_settings.inc");

a = get_kb_list("www/*/eMule");
if (isnull(a)) exit(0);

foreach k (keys(a))
{
  v = eregmatch(string: k, pattern: "www/([0-9]+)/eMule");
  if (isnull(v)) continue;
  port = int(v[1]);
  ver = a[k];
  if (ver =~ "^0\.(30e|42[a-d])$") security_hole(port);
}
