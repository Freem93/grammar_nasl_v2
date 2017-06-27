#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18299);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-1655");
  script_bugtraq_id(13553);
  script_osvdb_id(20683);

  script_name(english:"AIM Smiley Icon Location Remote Denial Of Service");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is prone to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"According to the Windows registry, the remote host has installed on it a
version of AOL Instant Messenger that does not properly handle invalid
data passed as the location of a 'smiley' icon.  Such invalid data leads
to an application crash, possibly because of a buffer overflow." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/10");
 script_cvs_date("$Date: 2011/09/29 04:49:13 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

  script_summary(english:"Checks for smiley icon location denial of service vulnerability in AIM");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("aim_detect.nasl");
  script_require_keys("AIM/version");

  exit(0);
}


# Test an install.
ver = get_kb_item("AIM/version");
if (ver) {
  # There's a problem if the newest version is 5.9.3702 or below.
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) < 5 ||
    (
      int(iver[0]) == 5 && 
      (
        int(iver[1]) < 9 ||
        (int(iver[1]) == 9 && int(iver[2]) <= 3702)
      )
    )
  ) security_warning(get_kb_item("SMB/transport"));
}
