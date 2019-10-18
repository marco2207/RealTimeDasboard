public class auditLogsScanner {

    // lookback period
    private static integer lookbackHoursPeriod = -2;
    // List of Salesforce user ids to send the email to 
    private static List<String> sendEmailto = 
        new List<String> {'mdragoni@salesforce.com'};
    // List of Salesforce Platform Event bus
    private static String sendMessageto = 'ConfigChangePE__e';
    // List of sections to ignore from the audit log events
    private static Set<String> ignoreSections = 
        new Set<String> {'Static Resource'};
    // List of users to monitor
    private static List<String> usersToMonitor = 
        new List<String> {'superbadge@securityspec.md'};
    // Email subject
    private static String emailSubject = 'Unexpected Change has occured in Production';
    
    
    /*
        Sends an email to the Salesforce users defined by sendEmailTo
        @param body
        List of Strings to create the body of the email
    */
    public void sendEmailMessage(List<String> body) {
        if (body == NULL || body.isEmpty()) {
            System.debug('### sendEmailMessage: Mail body is null or empty');
            return;
        }

        // Construct the Single Email Message
        Messaging.SingleEmailMessage message = new Messaging.SingleEmailMessage();
        message.toAddresses = sendEmailto;
        message.subject = emailSubject;
        String messageBody = String.join(body, '\n\n');
        message.plainTextBody = messageBody;

        try {
            // Do not check for errors as nothing to do in that case
            // We just want to bail out gracefully
			System.debug('### sendEmailMessage: Sending Email to: ' + sendEmailto.get(0));
            Messaging.sendEmail(new Messaging.SingleEmailMessage[] {message});
        } catch(System.CalloutException e) {
            System.debug('ERROR:' + e);
        }
    }
    
    public void sendEventMessage(ConfigChangePE__e newsEvent) {
        System.debug('### sendEventMessage: Sending Event: ' + newsEvent);
        // Call method to publish events
        Database.SaveResult sr = EventBus.publish(newsEvent);
        
        // Inspect publishing result 
        if (sr.isSuccess()) {
            System.debug('sendEventMessage: Successfully published event.');
        } else {
            for(Database.Error err : sr.getErrors()) {
                System.debug('sendEventMessage: Error returned: ' +
                     err.getStatusCode() +
                     ' - ' +
                     err.getMessage());
            }
        }   
    }
    

    /*
        Get the audit log events that occured in a lookback 
        period and were triggered by specific users
        
        The default lookback period (lookbackHoursPeriod) is one hour
        This method calls sendEmailMessage to send an email with the events
    */
    public void parseAuditLogs() {
        System.debug('### parseAuditLogs: Inside parseAuditLogs 1');
        DateTime dt = System.Now().addHours(lookbackHoursPeriod);
        
		System.debug('### parseAuditLogs: Run query');
        // run SOQL on SetupAuditTrail filtering on UserName and CreatedDate
        List<SetupAuditTrail> queryResults = [SELECT CreatedDate, CreatedBy.UserName, 
                                              Action, Section, Display 
                                              FROM SetupAuditTrail 
                                              WHERE CreatedBy.UserName IN :usersToMonitor 
                                                    AND CreatedDate >=:dt 
                                              ORDER BY CreatedDate DESC];
        if (queryResults.isEmpty()) {
            System.debug('### parseAuditLogs: Query is empty !!');
            return;
        }

        // parse the query to build the body for the email + send eventMessage 
        List<String> emailBodyList = new List<String>();
        for (SetupAuditTrail log: queryResults) {
            if (ignoreSections.contains(log.section)) {
                System.debug('### parseAuditLogs: Inside IF ignoreSections !!');
                continue;
            }

           // System.debug('### parseAuditLogs: Build Mail body');
            String emailLine = 'User: ' + log.CreatedBy.UserName 
                               + ' Section: ' + log.Section + ' Action: ' 
                               + log.Action + ' Details: ' + log.Display;
            emailBodyList.add(emailLine);
           // System.debug('### parseAuditLogs: emailLine is: ' + emailLine);
            
            // Set event message and call method to publish
            System.debug('### parseAuditLogs: Build event');
            ConfigChangePE__e newsEvent = new ConfigChangePE__e(
               Username__c = log.CreatedBy.UserName, 
               Section__c = log.Section, 
               Detail__c = log.Display,
               Action__c = log.Action);
               
            // System.debug('### parseAuditLogs: Send message event');
            sendEventMessage(newsEvent);
            
        }
        
        if (!emailBodyList.isEmpty()) {
           // System.debug('### parseAuditLogs: Send email');
            sendEmailMessage(emailBodyList);
        }
    }
}
