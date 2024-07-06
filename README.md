# MDLOGGER

Rust lib: Multi-device logger 

<p>This library crate implements a logging system that is able to log message on different devices at same time.<br/>
Each device is managed by an object that implements <strong>LogHandler</strong> trait.<br/>
There are 4 predefined log handler:<br/>
<ul>
    <li><strong>Console</strong></li>
    <li><strong>Rolling file</strong></li>
    <li><strong>Network socket (udp, tcp, multicat)</strong></li>
    <li><strong>Unix domain socket (udp, tcp Windows OS tcp only)</strong></li>
</ul>

These predefined log handler are registered in the
<b>initialize</b> function.</br>
You can implement your own handler and register it [see **register_log_handler_factory** funtion in the documentation]  before call the initialize function.</br>
The logger is configured using a text file with a classic <b>.ini</b> syntax</p>

Logging message can be identify by a category (a free text tag that could be print out with in log message) and a type, there are 5 type of messages:</br>
<ol>
    <li><strong>Debug</strong></li>
    <li><strong>Info</strong></li>
    <li><strong>Warning</strong></li>
    <li><strong>Critical</strong></li>
    <li><strong>Fatal</strong></li>
</ol>

MDLogger can receive external command to change configuration at run time.

**[configuration file documntation](https://github.com/fstafforte/mdlogger/tree/develop/docs/mdlogger_configuration.pdf)**

**[external command documentation](https://github.com/fstafforte/mdlogger/tree/develop/docs/mdlogger_external_commands.pdf)**
# HOW MDLOGGER WORKS

To prevent a multi-threaded process from being slowed down as little as possible by log messaging, mdlogger creates its own logging thread where log messages are handled by different log hanlers created via the configuration file.
The log function (and the related macros) do nothing more than insert the messages into a queue and then release control to the application process as quickly as possible.
The queued messages will be dequeued by the log thread which will pass them to each log handler that will format them according to the configuration chosen for that handler which will then carry out its log function 

This software is under **[MIT OR Apache-2.0]** </br>**https://mit-license.org/**</br>**https://www.apache.org/licenses/LICENSE-2.0**</br>


## MSRV 1.76.0

## History

Rev. 0.1.0 First issue<br/>
Rev. 0.1.1 Correct configuration documentation