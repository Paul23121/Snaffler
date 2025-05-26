using SnaffCore.Concurrency;
using System;
using System.Collections.Generic;
using System.IO;
using static SnaffCore.Config.Options;

namespace SnaffCore.Classifiers
{
    public class DodderClassifier
    {
        private static readonly Dictionary<string, string> FileExtensions = new Dictionary<string, string>
        {
            { ".cmd", "start /B COMMAND" },
            { ".bat", "start /B COMMAND" },
            { ".ps1", "Start-Process -WindowStyle Hidden COMMAND" },
            { ".vbs", "CreateObject(\"WScript.Shell\").Run \"COMMAND\", 0, False" },
            { ".js", "new ActiveXObject(\"WScript.Shell\").Run(\"COMMAND\", 0, false)" }
        };

        public DodderClassifier()
        {
            // Constructor now empty
        }

        public bool ClassifyDodderFile(FileInfo fileInfo)
        {
            BlockingMq Mq = BlockingMq.GetMq();

            // Check if the file extension is one we're interested in
            if (!FileExtensions.ContainsKey(fileInfo.Extension.ToLower()))
            {
                return false;
            }

            // No trace message for every file to reduce noise

            try
            {
                // Calculate threshold dates
                DateTime lastAccessTimeThreshold = DateTime.Now.AddDays(-MyOptions.DodderAccessDaysThreshold);
                DateTime lastModifyTimeThreshold = DateTime.Now.AddMonths(-MyOptions.DodderModifyMonthsThreshold);

                // Check if the file meets our criteria:
                // - Accessed recently (within threshold days)
                // - But not modified recently (older than threshold months)
                if (fileInfo.LastAccessTime > lastAccessTimeThreshold && 
                    fileInfo.LastWriteTime < lastModifyTimeThreshold)
                {
                    // Only log for matching files
                    Mq.Trace($"DodderHunt match: {fileInfo.FullName}");
                    Mq.Trace($"  LastAccess: {fileInfo.LastAccessTime}, LastWrite: {fileInfo.LastWriteTime}");

                    // Check write permissions explicitly
                    bool canRead = false;
                    bool canWrite = false;
                    bool canModify = false;

                    try {
                        FileInfo testFileInfo = new FileInfo(fileInfo.FullName);
                        // Check if we can read the file
                        using (FileStream fs = testFileInfo.OpenRead())
                        {
                            canRead = true;
                        }
                    }
                    catch (Exception)
                    {
                        // Can't read, don't set the flag
                    }

                    try {
                        // Check if we can write to the file
                        using (FileStream fs = File.Open(fileInfo.FullName, FileMode.Open, FileAccess.Write))
                        {
                            canWrite = true;
                        }
                    }
                    catch (Exception)
                    {
                        // Can't write, don't set the flag
                    }

                    try {
                        // Check if we can modify attributes
                        DateTime originalLastWriteTime = fileInfo.LastWriteTime;
                        File.SetLastWriteTime(fileInfo.FullName, fileInfo.LastWriteTime);
                        canModify = true;
                    }
                    catch (Exception)
                    {
                        // Can't modify, don't set the flag
                    }

                    // Create a result to send to the user
                    string matchedRuleName = "DodderHunt";
                    ClassifierRule rule = new ClassifierRule
                    {
                        RuleName = matchedRuleName,
                        Triage = canWrite ? Triage.Red : Triage.Yellow  // Red only if we can write to it
                    };

                    // Create the file access rights string (e.g. "RWM" if we have all permissions)
                    string accessRights = "";
                    if (canRead) accessRights += "R";
                    if (canWrite) accessRights += "W";
                    if (canModify) accessRights += "M";

                    string matchContext = $"LastAccessTime: {fileInfo.LastAccessTime}, LastWriteTime: {fileInfo.LastWriteTime}, " +
                                          $"Permissions: {accessRights}, Extension: {fileInfo.Extension}";

                    FileResult fileResult = new FileResult(fileInfo)
                    {
                        MatchedRule = rule,
                        TextResult = new TextResult
                        {
                            MatchedStrings = new List<string> { "DodderHunt Persistence Candidate" },
                            MatchContext = matchContext
                        }
                    };

                    // Add RW status explicitly
                    fileResult.RwStatus = new EffectiveAccess.RwStatus();
                    fileResult.RwStatus.CanRead = canRead;
                    fileResult.RwStatus.CanWrite = canWrite;
                    fileResult.RwStatus.CanModify = canModify;

                    Mq.FileResult(fileResult);
                    return true;
                }
            }
            catch (Exception ex)
            {
                Mq.Error("Error in DodderClassifier processing file " + fileInfo.FullName + ": " + ex.Message);
                Mq.Trace(ex.ToString());
                throw; // Rethrow to be caught by the caller
            }

            return false;
        }
    }
}
