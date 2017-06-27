#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24233);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-0391");
  script_bugtraq_id(22128);
  script_osvdb_id(33554);

  script_name(english:"BitDefender Client Log Creation Functionality Format String");
  script_summary(english:"Checks date of BitDefender's virus signatures");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is prone to a
local format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of BitDefender installed on the remote host fails to
sanitize scan job settings of format strings.  By leveraging this
flaw, a local attacker may be able to crash the antivirus application
or possibly even gain complete control of the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jan/455" );
 # http://web.archive.org/web/20070124111724/http://www.bitdefender.com/KB325-en--Format-string-vulnerability.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d320fd8e" );
 script_set_attribute(attribute:"solution", value:
"Run BitDefender's regular update function." );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/19");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/01/18");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:bitdefender:bitdefender_client:professional_plus");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("bitdefender_installed.nasl");
  script_require_keys("Antivirus/BitDefender/Sigs");

  exit(0);
}


sigs = get_kb_item("Antivirus/BitDefender/Sigs");
if (sigs && int(sigs) < 420778) security_hole(get_kb_item("SMB/transport"));
