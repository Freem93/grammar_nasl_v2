#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82798);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2015-3006");
  script_bugtraq_id(74020);
  script_osvdb_id(120483);
  script_xref(name:"JSA", value:"JSA10678");

  script_name(english:"Juniper Junos QFX Low Entropy Vulnerability (JSA10678)");
  script_summary(english:"Checks the Junos version and model.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a low entropy vulnerability due to an
insufficient number of bytes being collected from the RANDOM_INTERRUPT
entropy source when the device is first booted, thus resulting in the
generation of weak SSH keys or SSL/TLS certificates.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10678");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10678.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (
  'QFX3500' >!< model &&
  'QFX3600' >!< model
) audit(AUDIT_DEVICE_NOT_VULN, model);

fixes = make_array();
fixes['12.2X50'] = '12.2X50-D70';
fixes['13.1X50'] = '13.1X50-D30';
fixes['13.2X52'] = '13.2X52-D15';
fixes['14.1X53'] = '14.1X53-D10';

if (ver =~ '^13.2X51-')
{
  if (_junos_x_ver_compare(ver, '13.2X51-D25') > 0)
    fixes['13.2X51'] = '13.2X51-D30';
  else
    fixes['13.2X51'] = '13.2X51-D25';
}

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_warning(port:0, extra:report);
}
else security_warning(0);
