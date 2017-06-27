#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93524);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id("CVE-2016-6936");
  script_bugtraq_id(92926);
  script_osvdb_id(144137);

  script_name(english:"Adobe AIR for Mac <= 22.0.0.153 Android Applications Runtime Analytics MitM (APSB16-31)");
  script_summary(english:"Checks the version of AIR.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by a man-in-the-middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe AIR installed on the remote Mac OS X host is
prior or equal to version 22.0.0.153. It is, therefore, affected by a
man-in-the-middle (MitM) vulnerability due to the cleartext
transmission of runtime analytics for AIR applications on Android. A
MitM attacker can exploit this to disclose or tamper with the runtime
analytics.

Note that Nessus has not tested for this issues but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/air/apsb16-31.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR version 23.0.0.257 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_air_installed.nasl");
  script_require_keys("MacOSX/Adobe_AIR/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/Adobe_AIR";
version = get_kb_item_or_exit(kb_base+"/Version");
path = get_kb_item_or_exit(kb_base+"/Path");

# nb: we're checking for versions less than *or equal to* the cutoff!
cutoff_version = '22.0.0.153';
fixed_version_for_report = '23.0.0.257';

if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version_for_report +
      '\n';
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version, path);

