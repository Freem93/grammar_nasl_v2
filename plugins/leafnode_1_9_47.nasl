#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42260);
 script_version ("$Revision: 1.6 $");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");

 script_cve_id("CVE-2004-2068");
 script_osvdb_id(3441);

 script_name(english:"leafnode fetchnews DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote Leafnode NNTP server is
vulnerable to a denial of service attack.  Specifically, it may hang
without consuming CPU when attempting to read a news article with
missing mandatory headers.  This means that news will not be updated
until the fetchnews process is killed. 

Note that Nessus did not actually test for the flaw but instead has
relied on the version in Leafnode's banner so this may be a false
positive.");
 script_set_attribute(attribute:"see_also", value: "http://leafnode.sourceforge.net/leafnode-SA-2004-01.txt");
 script_set_attribute(attribute:"solution", value: "Upgrade to 1.9.48 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/10/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/01/09");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Check Leafnode version number for flaws");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("nntpserver_detect.nasl");
 script_require_ports("Services/nntp", 119);
 script_require_keys("nntp/leafnode");
 exit(0);
}

#

port = get_kb_item("Services/nntp");
if (! port) port = 119;
if (! get_port_state(port)) exit(0);

k = string("nntp/banner/", port);
b = get_kb_item(k);
if (! b)
{
  soc = open_sock_tcp(port);
  if (! soc) exit(0);
  b = recv_line(socket: soc, length: 2048);
  close(soc);
}

# Example of banner:
# 200 Leafnode NNTP Daemon, version 1.9.32.rel running at localhost (my fqdn: www.nessus.org)

if ("Leafnode" >< b)
{
  if (ereg(string: b, pattern: "version +1\.9\.([3-9]|[1-3][0-9]|4[0-7])[^0-9]"))
  {
    security_warning(port: port);
  }
}
