import React from 'react';

type Props = {
    value: number; // 0 to 100
};

const getColor = (value: number) => {
    if (value < 20) return 'stroke-systemRed';
    if (value < 30) return 'stroke-systemOrange';
    if (value < 50) return 'stroke-systemYellow';
    return 'stroke-systemGreen';
};

const ProgressBar = ({ value }: Props) => {
    const radius = 50;
    const stroke = 10;
    const normalizedRadius = radius - stroke / 2;
    const circumference = 2 * Math.PI * normalizedRadius;
    const strokeDashoffset = circumference - (value / 100) * circumference;
    const colorClass = getColor(value);

    return (
        <div className="relative w-28 h-28">
            <svg height="100%" width="100%" className="transform -rotate-90">
                <circle
                    stroke="currentColor"
                    strokeWidth={stroke}
                    fill="transparent"
                    r={normalizedRadius}
                    cx="50%"
                    cy="50%"
                    className="text-gray-300"
                />
                <circle
                    strokeLinecap="round"
                    strokeWidth={stroke}
                    fill="transparent"
                    r={normalizedRadius}
                    cx="50%"
                    cy="50%"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    className={`transition-all duration-300 ${colorClass}`}
                />
            </svg>

            <div className="absolute inset-0 flex items-center justify-center text-xl font-semibold">
                <div className='flex flex-col items-center justify-center'>
                    {value}%
                    <div className='text-[12px]'>Analyzing </div>
                </div>
            </div>
        </div>
    );
};

export default ProgressBar;
