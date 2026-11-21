import { mount } from 'svelte';
import App from './App.svelte';
import './styles.css';

const root = document.getElementById('root');
if (!root) throw new Error('Application root is missing');

mount(App, { target: root });
