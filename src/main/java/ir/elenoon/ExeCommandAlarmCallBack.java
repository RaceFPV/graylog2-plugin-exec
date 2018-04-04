package ir.elenoon;

import java.io.IOException;
import java.util.Map;

import org.graylog2.plugin.alarms.AlertCondition.CheckResult;
import org.graylog2.plugin.alarms.callbacks.AlarmCallback;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackConfigurationException;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackException;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationException;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.streams.Stream;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import java.io.FileWriter;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * This is the plugin. Your class should implement one of the existing plugin
 * interfaces. (i.e. AlarmCallback, MessageInput, MessageOutput)
 */
public class ExeCommandAlarmCallBack implements AlarmCallback{
	private Configuration configs;
	 private FileWriter log = null;


	@Override
	public void initialize(Configuration stream)
			throws AlarmCallbackConfigurationException {
		configs = new Configuration(stream.getSource());

		// copied from telegram plugin)
		 String logFilepath = configs.getString("filelog");
		 if (logFilepath != null && logFilepath.length() > 0) {
				 try {
						 log = new FileWriter(logFilepath, true);
						 log.write("Logging started\n");
						 log.flush();
				 } catch (IOException e) {
						 e.printStackTrace();
				 }
		 }
	}

	@Override
	public void call(Stream stream, CheckResult result)
			throws AlarmCallbackException {
		try {
			//
			// copied from graylog-plugin-sensu
			//

			// alert & messages attribs
			String output = new String();
			String title =  stream.getTitle();
			String alertDescription = result.getResultDescription();
			String time = result.getTriggeredAt().toString();
			String alertCondition = result.getTriggeredCondition().toString();
			String messageBacklog = new String();
			if (result.getMatchingMessages().size() == 0) {
				messageBacklog += "No message backlog available.";
			} else {
				for (MessageSummary message : result.getMatchingMessages()) {
					messageBacklog += message.getMessage();
				}
			}

			// output message for debuging
			output += "Stream \"" + title + "\" raised alert. \n";
			output += "Alert description: " + alertDescription + "\n";
			output += "Triggered at: " + time + "\n";
			output += "Alert condition: " +  alertCondition;
			output += "Last messages accounting for this alert: \n";
			output += messageBacklog + "\n";

			// expand the command
			String bashCommand = configs.getString("bashCommand");
			output += "Bash command: " + bashCommand + "\n";
			bashCommand = findAndReplaceAll("\\$\\{message\\}", messageBacklog, bashCommand);
			bashCommand = findAndReplaceAll("\\$\\{alertDescription\\}", alertDescription, bashCommand);
			bashCommand = findAndReplaceAll("\\$\\{alertCondition\\}", alertCondition, bashCommand);
			if (result.getMatchingMessages().size() != 0) {
				for (MessageSummary message : result.getMatchingMessages()) {
					for (Map.Entry<String, Object> entry : message.getFields().entrySet()) {
						bashCommand = findAndReplaceAll("\\$\\{" + entry.getKey() + "\\}", entry.getValue().toString(), bashCommand);
					}
				}
			}
			output += "Bash command expanded: " + bashCommand + "\n";

			// write the log
			if (log != null) {
				log.write(output);
				log.write('\n');
				log.flush();
			}

			// exec the command
			Runtime.getRuntime().exec(new String[]{"bash","-c",bashCommand});

		} catch (IOException e) {
			e.printStackTrace();
		}
	}


	private static String findAndReplaceAll( String pattern, String replaceWith, String inputString)	{
    Pattern p = Pattern.compile(pattern);
    Matcher matcher = p.matcher(inputString);
    return matcher.replaceAll(replaceWith);
	}

	@Override
	public void checkConfiguration() throws ConfigurationException {
		String command = configs.getString("bashCommand");
		if (command.isEmpty())
			throw new ConfigurationException("Fill the bash command field.");
	}

	@Override
	public Map<String, Object> getAttributes() {
		return configs.getSource();
	}

	@Override
	public String getName() {
		return "Execute Command Alarm Callback";
	}

	@Override
	public ConfigurationRequest getRequestedConfiguration() {
		final ConfigurationRequest configurationRequest = new ConfigurationRequest();
		configurationRequest.addField(new TextField("bashCommand", "Bash Command", "", "use \"${message}\", \"${alertDescription}\", \"${alertCondition}\" or \"${fieldName}\" which contains any field name of message to forward graylog info", ConfigurationField.Optional.NOT_OPTIONAL));
		// Manu (20170726). Add filelog to debug
		configurationRequest.addField(new TextField("filelog", "File log", "/tmp/execCommandCallBack.log", "File path for debug logging"));
		return configurationRequest;
	}
}
