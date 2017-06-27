#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15819);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2016/11/17 21:38:53 $");

 script_cve_id(
  "CVE-2004-1011",
  "CVE-2004-1012",
  "CVE-2004-1013",
  "CVE-2004-1015",
  "CVE-2004-1067"
 );
 script_bugtraq_id(11729, 11738);
 script_osvdb_id(12096, 12097, 12098, 12290, 12348);

 script_name(english:"Cyrus IMAP Server < 2.2.10 Multiple Remote Overflows");
 script_summary(english:"Checks for a Cyrus IMAPD version");

 script_set_attribute(attribute:"synopsis", value:"The remote IMAP server has multiple buffer overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote Cyrus IMAPD server is vulnerable
to one pre-authentication buffer overflow, as well as three post-
authentication buffer overflows. A remote attacker could exploit these
issues to crash the server, or possibly execute arbitrary code.");
 script_set_attribute(attribute:"solution", value:"Upgrade to Cyrus IMAPD 2.2.10 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/23");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:cmu:cyrus_imap_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencie("cyrus_imap_prelogin_overflow.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/imap", 143);

 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# nb: banner checks of open source software are prone to false-positives
#     so we only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_service(svc:"imap", default: 143, exit_on_fail: 1);
if (get_kb_item("imap/"+port+"/false_imap")) exit(1);

kb = get_kb_item_or_exit("imap/" + port + "/Cyrus");

if ( egrep(pattern:"^(1\..*|2\.([0-1]\..*|2\.[0-9][^0-9].*))", string:kb ))
	security_hole ( port );
