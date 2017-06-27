#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47780);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2010-1966");
  script_bugtraq_id(41578);
  script_osvdb_id(66272);
  script_xref(name:"Secunia", value:"40550");

  script_name(english:"HP Insight Control Power Management < 6.1 Local Unauthorized Access");
  script_summary(english:"Checks HP IPM version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A power management application installed on the remote Windows host
has a security bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of HP Insight Control Power Management installed on the
remote host is earlier than 6.1.  Such versions have an unspecified
local security bypass vulnerability."
  );
  # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c0228236
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f009f3a"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to HP Insight Control Power Management 6.1 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/07/12");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/07/12");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/07/20");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:insight_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_insight_power_mgmt_installed.nasl");
  script_require_keys("SMB/hp_ipm/path", "SMB/hp_ipm/ver");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");


path = get_kb_item_or_exit('SMB/hp_ipm/path');
ver = get_kb_item_or_exit('SMB/hp_ipm/ver');
port = kb_smb_transport();

if (ver_compare(ver:ver, fix:'6.1', strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\nPath    : ' + path +
      '\nVersion : ' + ver +
      '\nFix     : 6.1\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, 'HP IPM version '+ver+' is not affected.');
