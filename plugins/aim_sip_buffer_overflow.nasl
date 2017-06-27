#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42304);
  script_version("$Revision: 1.10 $");

  script_bugtraq_id(36849);
  script_osvdb_id(59368, 59369);

  script_name(english: "AOL AIM 'sipXtapi.dll' Multiple Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks version of AOL AIM.");
  script_set_attribute(
    attribute:'synopsis',
    value:
"The detected instant messenger client is affected by multiple buffer
overflow vulnerabilities."
  );

  script_set_attribute(
    attribute:'description',
    value:
"AOL AIM is affected by multiple buffer overflow vulnerabilities because
it fails to perform adequate boundary checks on user-supplied data.

Successful exploits may allow attackers to execute arbitrary code with
the privileges of the user running the software or cause an application
crash."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade to AOL AIM 6.8.7.7 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(
    attribute:'see_also',
    value:"http://www.zerodayinitiative.com/advisories/ZDI-08-097/"
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://www.zerodayinitiative.com/advisories/ZDI-08-098/"
  );

  script_set_attribute( attribute:'vuln_publication_date', value:'2008/06/10' );
  script_set_attribute( attribute:'patch_publication_date', value:'2008/06/11' );
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/10/29' );

 script_cvs_date("$Date: 2016/11/11 19:58:28 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:aol:aim");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("aim_detect.nasl");
  script_require_keys("AIM/version");

  exit(0);
}


# Test an install.
ver = get_kb_item("AIM/version");
if (!ver)
  exit(1, "The 'AIM/version' KB item is missing." );

# There's a problem if the AOL AIM version is below 6.8.7.7.
iver = split(ver, sep:'.', keep:FALSE);
if (
  int(iver[0]) < 6 ||
  ( int(iver[0]) == 6 &&
    ( int(iver[1]) < 8 ||
      ( int(iver[1]) == 8 &&
        ( int(iver[2]) < 7 ||
          ( int(iver[2]) == 7 && int(iver[3]) < 7 )
        )
      )
    )
  )
) security_hole(get_kb_item("SMB/transport"));
else exit(0, "The host is not affected since AIM "+ver+" is installed.");
