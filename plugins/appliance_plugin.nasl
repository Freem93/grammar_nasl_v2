# @DEPRECATED@
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77329);
  script_version ("1.1");
  script_cvs_date("$Date: 2014/08/22 15:35:30 $");

  script_name(english:"Tenable Appliance Check (deprecated)");
  script_summary(english:"This plugin has been deprecated.");

  script_set_attribute(
    attribute:"synopsis",
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This plugin was previously used to detect if the local scanner was
using the Tenable Appliance. It is no longer needed, and is now
obsolete."
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor",value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  exit(0);
}

# obsoleted by dont_scan_localhost.nbin
exit(0);
