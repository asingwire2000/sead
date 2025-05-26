import { useEffect, useState } from 'react'
import SettingsButton from './components/settings'
import ProgressBar from './components/progressLoader';

function App() {
  const [message, setMessage] = useState<string | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [currentUrl, setCurrentUrl] = useState('');
  const [riskState, setRiskState] = useState('');
  const [scoreValue, setScoreValue] = useState<number | null>(null);
  const [reportingSource, setReportingSource] = useState('');
  const [sources, setSources] = useState<any>({});
  const [impactMessage, setImpactMessage] = useState('');
  const [errors, setErrors] = useState<string[]>([]);
  const [history, setHistory] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [blockNavigation, setBlockNavigation] = useState(false);


  useEffect(() => {
    const updateUI = (isLoading: boolean = false) => {
      setIsLoading(isLoading);

      browser.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const url = tabs[0]?.url || '';
        setCurrentUrl(url);

        browser.storage.local.get(['linkHistory'], (result) => {
          const linkHistory = result.linkHistory || [];
          setHistory(linkHistory);

          const currentEntry = linkHistory.find((entry: { url: string; }) => entry.url === url);

          if (currentEntry) {
            setRiskState(currentEntry.state);
            setScoreValue(currentEntry.vulnerabilityScore);
            setReportingSource(currentEntry.reportingSource);
            setSources(currentEntry.sources);
            setImpactMessage(currentEntry.impact);
            setErrors(currentEntry.errors?.length > 0 ? currentEntry.errors : ['No errors detected. All checks completed successfully! 😊']);
          } else {
            setRiskState('Not yet analyzed');
            setScoreValue(null);
            setReportingSource('Not yet analyzed');
            setSources({});
            setImpactMessage('Please wait for analysis... 😊');
            setErrors([isLoading ? 'Analysis in progress...' : 'Waiting for analysis to complete...']);
          }
        });
      });
    };

    setTimeout(() => updateUI(), 1000);

    browser.storage.local.get(['blockNavigation'], (result) => {
      setBlockNavigation(result.blockNavigation || false);
    });

    const handleMessage = (message: any) => {
      if (message.action === 'analysisStarted') {
        updateUI(true);
        setProgress(0);
      } else if (message.action === 'progressUpdate') {
        setProgress(message.progress);
      } else if (message.action === 'historyUpdated') {
        updateUI();
      }
    };

    browser.runtime.onMessage.addListener(handleMessage);

    return () => {
      browser.runtime.onMessage.removeListener(handleMessage);
    };
  }, []);



  const handleBlockNavigationChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const checked = e.target.checked;
    setBlockNavigation(checked);
    browser.storage.local.set({ blockNavigation: checked });
  };

  const handleCancelAnalysis = () => {
    browser.runtime.sendMessage({ action: 'cancelAnalysis' }, () => {
      setIsLoading(false);
    });
  };

  const handleRefresh = () => {
    browser.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url;
      /* if (url) {
         browser.runtime.sendMessage({ action: 'clearCacheAndHistoryForUrl', url }, () => {
           browser.tabs.reload(tabs[0].id, () => {
             setIsLoading(true);
           });
         });
       }*/
    });
  };

  const handleReportPhishing = () => {
    const submitUrl = `https://www.phishtank.com/add_web_phish.php?url=${encodeURIComponent(currentUrl)}`;
    browser.tabs.create({ url: submitUrl });
  };

  // {typeof progress === 'number' && <ProgressBar value={progress} />}


  return (
    <>
      <div className='p-1'>
        <div className='flex items-center p-8 border border-separator rounded'>
          <div className='flex  items-center flex-col w-[600px]'>
            <div className='flex items-center justify-between  mb-3 w-full bg-backgroundLayer1 p-4 rounded'><h1 className='text-3xl font-bold'>SEAD </h1><SettingsButton />
            </div>

            <div className='flex text-xl font-bold justify-start w-full mb-4'>{currentUrl}</div>


            <div
              className='flex w-full justify-start mb-4'>
              <div className='border border-separator p-4 rounded-lg shadow-lg'>
                {riskState && (
                  <div className="grid grid-cols-2 gap-2">
                    <div className="font-semibold">Risk</div>
                    <div className="">{riskState}</div>
                  </div>
                )}
                <div className="my-2 h-px w-full bg-separator" />
                {scoreValue !== null && (
                  <div className="grid grid-cols-2 gap-2">
                    <div className="font-semibold">Score</div>
                    <div className="">{scoreValue}%</div>
                  </div>)}
                <div className="my-2 h-px w-full bg-separator" />
                {reportingSource && (
                  <div className="grid grid-cols-2 gap-2">
                    <div className="font-semibold">Primary Source</div>
                    <div className="">{reportingSource}</div>
                  </div>)}
                <div className="my-2 h-px w-full bg-separator" />
                <p className='mt-4'>{impactMessage}</p>
              </div>
            </div>


            <ul>
              {errors.map((error, i) => (
                <li key={i}>{error}</li>
              ))}
            </ul>

            {/*<button onClick={handleCancelAnalysis}>Cancel Analysis</button>
            <button onClick={handleRefresh}>Refresh Analysis</button>
            <button onClick={handleReportPhishing}>Report Phishing</button>*/}


            <div
              className='flex w-full justify-start mb-4'>
              <div className=''>
                <ul>
                  {history.map((entry, i) => (
                    <li key={i} className="">
                      <div className="overflow-x-auto">
                        <table className="min-w-full text-sm text-left border border-separator rounded-lg shadow-lg p-4">
                          <thead className="bg-backgrounLayer1 uppercase tracking-wide">
                            <tr>
                              <th className="px-4 py-2">Source</th>
                              <th className="px-4 py-2">Status</th>
                            </tr>
                          </thead>
                          <tbody>
                            {Object.entries(entry.sources).map(([source, status]) => (
                              <tr key={source} className="border-t border-separator">
                                <td className="px-4 py-2 font-medium  capitalize">{source}</td>
                                <td className="px-4 py-2">
                                  <span
                                    className={`px-2 py-1 rounded-lg w-[100px] justify-center text-xs font-semibold 
                      ${status === 'Suspicious' ? 'text-systemYellow border border-systemYellow' :
                                        status === 'Malicious' ? 'border border-systemRed text-systemRed' :
                                          status === 'Safe' ? 'border border-systemGreen text-systemGreen' :
                                            'border border-gray1 text-gray1'}`}
                                  >
                                    {`${status}`}
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </li>
                  ))}
                </ul>

              </div>
            </div>

          </div>
        </div>
      </div>
    </>
  )
}

export default App
