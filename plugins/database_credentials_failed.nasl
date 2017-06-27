#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91822);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/06/24 21:29:02 $");

  script_name(english:"Database Authentication Failure(s) for Provided Credentials");
  script_summary(english:"Displays information about the scan.");

  script_set_attribute(attribute:"synopsis", value:
"Database credentialed checks for one or more detected database systems
have been disabled.");
  script_set_attribute(attribute:"description", value:
"Nessus was unable to log into one or more detected database systems
for which credentials have been provided in order to perform authenticated
checks.");
  script_set_attribute(attribute:"solution", value:
"Address the problem(s) so that the credentialed checks can be
executed.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_END);

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Settings");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("misc_func.inc");
include("global_settings.inc");

failures = get_kb_list_or_exit("DB_Auth/*/Failure");

report = '\nNessus was unable to log into the following database systems for which\n' +
         'credentials have been provided :\n\n';

foreach fail (keys(failures))
{
  tmp = split(fail, sep:'/', keep:FALSE);
  db_name = tmp[1];
  db_port = tmp[2];

  details = get_kb_item(fail + "Details");

  # this should never happen, but we should provide some default just in case
  if(isnull(details)) details = 'No details available';

  if(details[strlen(details) - 1] == '\n')
    details = substr(details, 0, strlen(details) - 2);

  report += '  Database        : ' + db_name + '\n' +
            '  Port            : ' + db_port + '\n' + 
            '  Failure details :\n' + details + '\n\n'; 
}

security_note(port:0, extra:report);
