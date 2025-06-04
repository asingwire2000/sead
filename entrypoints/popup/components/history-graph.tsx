import { Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, CartesianGrid, Legend, Cell, Area, AreaChart, PieChart, Pie, Text } from 'recharts';


export const processGraphData = (history: any[]) => {
    return history.map(entry => ({
        url: entry.url,
        timestamp: new Date(entry.timestamp).toLocaleString(),
        vulnerabilityScore: (100 - entry.vulnerabilityScore) || 100,
        state: entry.state || 'Unknown'
    }));
};


export const RiskGraph = ({ data }: { data: any[] }) => {
    return (
        <div className="w-full h-[200px] mb-4 p-4 border border-separator rounded-lg shadow-lg">
            <h2 className="text-xl font-semibold mb-2">Site Risk History</h2>
            <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data} margin={{ top: 10, right: 0, left: 0, bottom: 0 }}>
                    <defs>
                        <linearGradient id="lineGradient" x1="0" y1="0" x2="1" y2="0">
                            <stop offset="0%" stopColor="#10b981" />
                            <stop offset="100%" stopColor="#059669" />
                        </linearGradient>
                        <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#10b981" stopOpacity={0.8} />
                            <stop offset="95%" stopColor="#10b981" stopOpacity={0.4} />
                        </linearGradient>
                    </defs>
                    {/* Removed CartesianGrid completely */}
                    <XAxis
                        dataKey="timestamp"
                        tick={{ fontSize: 10 }}
                        tickMargin={10}
                        axisLine={{ stroke: '#e5e7eb' }}
                        tickLine={{ stroke: '#e5e7eb' }}
                    />
                    <YAxis
                        domain={[0, 100]}
                        tickCount={6}
                        axisLine={{ stroke: '#e5e7eb' }}
                        tickLine={{ stroke: '#e5e7eb' }}
                    />
                    <Tooltip
                        contentStyle={{
                            fontSize: '12px',
                            borderRadius: '8px',
                            boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
                            background: '#f8fafc',
                            border: 'none'
                        }}
                    />
                    <Legend />
                    <Area
                        type="monotone"
                        dataKey="vulnerabilityScore"
                        fill="url(#areaGradient)"
                        stroke="none"
                        activeDot={false}
                    />
                    <Line
                        type="monotone"
                        dataKey="vulnerabilityScore"
                        name="Risk Score"
                        stroke="url(#lineGradient)"
                        strokeWidth={3}
                        dot={false}
                        activeDot={{
                            r: 6,
                            fill: '#fff',
                            stroke: '#059669',
                            strokeWidth: 2
                        }}
                    />
                </AreaChart>
            </ResponsiveContainer>
        </div>
    );
};


export const RiskGauge = ({ score }: { score: number }) => {
    const needleAngle = (score / 100) * 180 - 90;

    const gaugeData = [
        { name: 'Safe', value: 30, color: '#10b981' },
        { name: 'Suspicious', value: 30, color: '#f59e0b' },
        { name: 'Danger', value: 30, color: '#ef4444' },
    ];

    return (
        <div className="w-full h-[200px] flex flex-col items-center relative border border-separator shadow-xl rounded-lg p-4">
            <h2 className="text-lg font-semibold mb-1">Current Risk Level</h2>

            <div className="relative w-full h-[160px]">
                {/* Render the gauge */}
                <ResponsiveContainer width="100%" height="100%">
                    <PieChart margin={{ top: 0, right: 10, left: 10, bottom: 10 }}>
                        <Pie
                            data={gaugeData}
                            cx="50%"
                            cy="60%" // place arc at the lower part
                            startAngle={180}
                            endAngle={0}
                            innerRadius="80%"
                            outerRadius="100%"
                            dataKey="value"
                        >
                            {gaugeData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                        </Pie>
                    </PieChart>
                </ResponsiveContainer>

                {/* Needle precisely centered on arc */}
                <svg
                    className="absolute inset-0 w-full h-full pointer-events-none"
                    viewBox="0 0 100 100"
                    preserveAspectRatio="none"
                >
                    <g transform="translate(50,55)"> {/* center x=50, y=cy% */}
                        <line
                            x1={0}
                            y1={0}
                            x2={0}
                            y2={-25}
                            stroke="#374151"
                            strokeWidth={2.5}
                            transform={`rotate(${needleAngle})`}
                        />
                        <circle cx={0} cy={0} r={3} fill="#374151" />
                    </g>
                </svg>


                {/* Labels */}
                <div className="absolute bottom-5 left-10 right-10 flex justify-center gap-2 px-4 text-xs text-center">
                    <span className="w-16 text-[#10b981]">Safe</span>
                    <span className="w-20 text-[#f59e0b]">Suspicious</span>
                    <span className="w-16 text-[#ef4444]">Malicious</span>
                </div>

            </div>
        </div>
    );
};
