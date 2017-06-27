#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if(description)
{
  script_id(16152);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id("CVE-2004-1150");
  script_bugtraq_id(12245, 12381);
  script_osvdb_id(12858, 12922, 12923, 12924);

  script_name(english:"Winamp < 5.0.8c Multiple Unspecified Vulnerabilities");

  script_set_attribute(
    attribute:'synopsis',
    value:'The version of Winamp on the remote host has multiple vulnerabilities.'
  );

  script_set_attribute(
    attribute:'description',
    value:
"The version of Winamp installed on the remote host has various
unspecified vulnerabilities that may allow an attacker to execute
arbitrary code on the remote host. 

An attacker may exploit these flaws by sending malformed files to a
victim on the remote host."
  );

  script_set_attribute(attribute:'solution', value:"Upgrade to Winamp 5.0.8c or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=110684140108614&w=2'
  );

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/13");
  script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/22");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_summary(english:"Determines the version of Winamp");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

#

version = get_kb_item("SMB/Winamp/Version");
if ( ! version ) exit(0);

if(version =~ "^([0-4]\.|5\.0\.[0-8]\.)")
  security_warning(get_kb_item("SMB/transport"));
