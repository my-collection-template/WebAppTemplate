using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Web;

namespace WebAppTemplate.Infrastructure
{
    /// <summary>
    /// Loging on trace system
    /// </summary>
    public static class TracingSystem
    {
        private static TraceSource logger = new TraceSource("Tracer");

        /// <summary>
        /// Traces an Event with <see cref="TraceEventType.Error"/> event Type and with Event ID equals to "3".
        /// </summary>
        /// <param name="message">The message which will be traced.</param>
        /// <remarks>This method will use the <see cref="TraceSource"/> object which returned from <see cref="MovmentTracer"/> property.</remarks>
        /// <example>This method should be called to trace an exception in the application.</example>
        public static void TraceException(Exception ex)
        {
            logger.TraceEvent(TraceEventType.Error, 3, ex.ToString());
        }

        public static void TraceException(string message, Exception ex)
        {
            logger.TraceEvent(TraceEventType.Error, 3, message + Environment.NewLine + ex.ToString());
        }

        public static void TraceError(string message)
        {
            logger.TraceEvent(TraceEventType.Error, 4, message);
        }

        public static void TraceCriticalError(string message)
        {
            logger.TraceEvent(TraceEventType.Critical, 5, message);
        }

        public static void TraceInformation(string message)
        {
            logger.TraceEvent(TraceEventType.Information, 6, message);
        }
    }
}