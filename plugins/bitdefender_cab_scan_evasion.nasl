#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38829);
  script_version("$Revision: 1.7 $");

  script_bugtraq_id(34580);

  script_name(english:"BitDefender CAB Scan Evasion");
  script_summary(english:"Checks the last update date of BitDefender");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an antivirus application that is
susceptible to a scan evasion attack." );
  script_set_attribute(attribute:"description", value:
"The remote version of BitDefender Antivirus is running with a
signature update before April 13, 2009.  Such versions are affected by
a scan evasion vulnerability.  An attacker can exploit this flaw to
package malicious code in a specially crafted 'CAB' file so that it
will not be detected by the scan engine." );
   # http://blog.zoller.lu/2009/04/bitdefender-generic-bypassevasion-cab.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?250f2e10" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/502748/30/0/threaded" );
  script_set_attribute(attribute:"solution", value:
"Ensure the scan engine is using a signature update of April 13, 2009
or later as that is reportedly when the vendor is said to have 
deployed a patch for the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/20");
 script_cvs_date("$Date: 2012/08/23 21:19:09 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:bitdefender:antivirus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");
  
  script_dependencies("bitdefender_installed.nasl");
  script_require_keys("Antivirus/BitDefender/Sigs_Update");

  exit(0);
}

include("global_settings.inc");

sigs_update = get_kb_item("Antivirus/BitDefender/Sigs_Update");
if (
  sigs_update &&
  (
    sigs_update =~ "^[A-Za-z]{3}.*(1[0-9]{3}|200[0-8])$" ||
    sigs_update =~ "^[A-Za-z]{3}(\s)+(Jan|Feb|Mar).*2009$" ||
    sigs_update =~ "^[A-Za-z]{3}(\s)+Apr ( |(0[0-9]|1[0-2])).*2009$"
  )
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Last update: ", sigs_update, "\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}

