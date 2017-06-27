#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63519);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/12 23:01:51 $");

  script_osvdb_id(89477);

  script_name(english:"Juniper Junos J-Web URL Encoding Heap-Based Buffer Overflow (PSN-2013-01-807)");
  script_summary(english:"Checks Junos version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Junos device
has a heap-based buffer overflow in the J-Web component.  Sending an
unspecified request related to URL encoding can corrupt heap memory.  A
remote, unauthenticated attacker could exploit this to execute arbitrary
code."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?txtAlertNumber=PSN-2013-01-807
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7cc8b6e");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2013-01-807."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

fixes['11.4'] = '11.4R6';
fixes['12.1'] = '12.1S3';
fixes['12.2'] = '12.2R2';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_hole(port:0, extra:report);
}
else security_hole(0);
