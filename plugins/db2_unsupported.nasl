#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55690);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/08/03 21:23:24 $");

  script_name(english:"IBM DB2 Unsupported Version Detection");
  script_summary(english:"Checks if a DB2 version is unsupported.");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of a database server is running on the remote
host.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of IBM
DB2 on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg21168270");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of IBM DB2 that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", exit_on_fail:TRUE);

level = get_kb_item_or_exit(
  "DB2/" + port + "/Level",
  exit_code:1,
  msg:"Failed to extract the installed version of IBM DB2 listening on port "+port+"."
);

# nb: from 'End of Support Date (Extended)'.
eos_dates = make_array(
  '7.1', 'Jun 30, 2003',
  '7.2', 'Apr 30, 2005',
  '8.1', 'Apr 30, 2012',
  '8.2', 'Apr 30, 2012',
  '9.1', 'Apr 30, 2015'
#  '9.5', 'Apr 30, 2018',
#  '9.7', 'Sep 30, 2020',
#  '9.8', 'Apr 30, 2019',
#  '10.1', 'Sep 30, 2020',
#  '10.5', '',
#  '11.1', ''
);
withdrawl_announcements = make_array(
  '7.2', 'http://www-01.ibm.com/common/ssi/cgi-bin/ssialias?subtype=ca&infotype=an&appname=iSource&supplier=897&letternum=ENUS903-185',
  '8.1', 'http://www.ibm.com/common/ssi/cgi-bin/ssialias?subtype=ca&infotype=an&appname=iSource&supplier=897&letternum=ENUS907-125',
  '8.2', 'http://www.ibm.com/common/ssi/cgi-bin/ssialias?subtype=ca&infotype=an&appname=iSource&supplier=897&letternum=ENUS907-125',
  '9.1', 'http://www.ibm.com/common/ssi/ShowDoc.jsp?docURL=/common/ssi/rep_ca/6/897/ENUS910-286/index.html&breadCrum=DET001PT022&url=buttonpressed=DET002PT005&specific_index=DET001PEF502&DET015PGL002=DET001PEF011&submit.x=7&submit.y=8&lang=en_US'
#  '9.5', 'http://www-01.ibm.com/common/ssi/ShowDoc.wss?docURL=/common/ssi/rep_ca/0/897/ENUS913-220/index.html&lang=en&request_locale=en',
#  '9.7', 'http://www-01.ibm.com/common/ssi/ShowDoc.wss?docURL=/common/ssi/rep_ca/3/897/ENUS916-003/index.html&lang=en&request_locale=en',
#  '9.8', 'http://www-01.ibm.com/common/ssi/ShowDoc.wss?docURL=/common/ssi/rep_ca/7/897/ENUS915-117/index.html&lang=en&request_locale=en',
#  '10.1', 'http://www-01.ibm.com/common/ssi/ShowDoc.wss?docURL=/common/ssi/rep_ca/3/897/ENUS916-003/index.html&lang=en&request_locale=en'
);
# Mostly from https://www-304.ibm.com/support/docview.wss?uid=swg27007053
#
# nb: 9.1 reached EoS (base) on April 30, 2012 but remains in extended support
#     so we won't list it here any more.
# 9.5 EoS April 30, 2015 so removing it from the list
supported_versions = '11.1 / 10.5 / 10.1 / 9.8 / 9.7';

ver = split(level, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
version_highlevel = strcat(ver[0], '.', ver[1]);

if ((ver[0] <= 8) || (ver[0] == 9 && ver[1] < 5))
{
  register_unsupported_product(product_name:"IBM DB2",
                               version:tolower(level), cpe_base:"ibm:db2");

  if (report_verbosity > 0)
  {
    # Determine what data to report.
    data = make_array();
    data['Installed high-level version'] = version_highlevel;
    data['Supported versions'] = supported_versions;
    if (eos_dates[version_highlevel])
      data['End of support date (extended)'] = eos_dates[version_highlevel];
    if (withdrawl_announcements[version_highlevel])
      data['Withdrawl announcement'] = withdrawl_announcements[version_highlevel];

    # Figure out spacing.
    max_label_len = 0;
    foreach label (keys(data))
      if (strlen(label) > max_label_len) max_label_len = strlen(label);

    # Generate report.
    report = '';
    foreach label (sort(keys(data)))
      if (label =~ '^Installed')
        report += '  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + data[label] + '\n';

    foreach label (sort(keys(data)))
      if (label !~ '^(Installed|Supported)')
        report += '  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + data[label] + '\n';

    foreach label (sort(keys(data)))
      if (label =~ '^Supported')
        report += '  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + data[label] + '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}

exit(0, 'The IBM DB2 '+version_highlevel+' installation listening on port '+port+' is currently supported.');
